"""edr-lite 감시 Function (Cloud Run functions, Python 3.12 이상).

진입점
  on_log_entry : Cloud Logging 싱크 -> Pub/Sub 로 들어온 LogEntry 를 검증해 BigQuery 에 적재하고,
                 즉시 경보 조건(etw_stopped, etw_alive=false, 형식 위반)을 Discord 로 알린다.
  watchdog     : Cloud Scheduler 가 주기적으로 호출한다. heartbeat 공백과 seq 공백을
                 BigQuery 에서 계산해 알린다.

원칙
  - 게스트가 보낸 값은 신뢰할 수 없는 입력이다: 형식, 범위, 크기를 검증하고 통과하지 못하면 적재하지 않는다.
  - 경보 메시지에는 검증된 값(sid, 숫자, 고정 사유 코드)만 넣는다. 게스트가 정한 임의 문자열은 넣지 않는다.
  - 웹훅 주소는 환경변수(DISCORD_WEBHOOK_URL, Secret Manager 에서 주입)로만 받는다.
    코드·로그·문서에 적지 않는다.

환경변수 (모두 선택, 괄호 안은 기본값)
  BQ_DATASET (edr_logs), EVENTS_TABLE (events), ALERTS_TABLE (alerts),
  HEARTBEAT_SECS (10, 에이전트 heartbeat_secs 이상으로), LOOKBACK_HOURS (24),
  ALERT_REPEAT_MINUTES (30, 같은 경보를 다시 보내기까지의 간격), DISCORD_WEBHOOK_URL
"""

import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    import functions_framework
except ImportError:  # 로컬 단위 테스트 환경
    functions_framework = None

log = logging.getLogger("edr_monitor")

KINDS = frozenset({
    "agent_start", "agent_stop", "proc_start", "proc_existing", "proc_stop",
    "image_load", "net", "heartbeat", "etw_stopped", "etw_restarted",
})
SEVERITIES = frozenset({
    "DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY",
})
SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RFC3339_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z$")
MAX_SEQ = 10 ** 12
MAX_PAYLOAD_BYTES = 64 * 1024
GAP_GRACE_SECS = 60

# 세션별 현재 상태. 마지막 agent_start 이후의 이벤트만 본다 (재시작하면 seq 가 1부터 다시 시작).
SESSION_SQL = """
WITH base AS (
  SELECT sid, seq, kind, recv_time, dropped_queue, dropped_send
  FROM `{table}`
  WHERE recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @hours HOUR)
),
agg AS (
  SELECT sid,
         MAX(IF(kind = 'agent_start', recv_time, NULL)) AS last_start,
         MAX(IF(kind = 'agent_stop', recv_time, NULL)) AS last_stop
  FROM base GROUP BY sid
),
cur AS (
  SELECT b.*
  FROM base b JOIN agg a ON a.sid = b.sid
  WHERE a.last_start IS NULL OR b.recv_time >= a.last_start
),
hb AS (
  SELECT sid,
         ARRAY_AGG(STRUCT(seq, recv_time, dropped_queue, dropped_send)
                   ORDER BY seq DESC LIMIT 1)[OFFSET(0)] AS h
  FROM cur WHERE kind = 'heartbeat' GROUP BY sid
),
cnt AS (
  SELECT c.sid, COUNT(DISTINCT c.seq) AS received_le_hb
  FROM cur c JOIN hb ON hb.sid = c.sid AND c.seq <= hb.h.seq
  GROUP BY c.sid
)
SELECT a.sid, a.last_start, a.last_stop,
       hb.h.seq AS hb_seq, hb.h.recv_time AS last_hb,
       hb.h.dropped_queue AS dropped_queue, hb.h.dropped_send AS dropped_send,
       cnt.received_le_hb AS received_le_hb
FROM agg a
LEFT JOIN hb USING (sid)
LEFT JOIN cnt USING (sid)
"""


# ---------------------------------------------------------------- 검증 (순수 함수)
def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def validate_event(payload):
    """에이전트 이벤트(jsonPayload)를 검증한다. 반환: (필드 dict, None) 또는 (None, 사유 코드)."""
    if not isinstance(payload, dict):
        return None, "not_object"
    kind = payload.get("kind")
    if kind not in KINDS:
        return None, "unknown_kind"
    sid = payload.get("sid")
    if not isinstance(sid, str) or not SID_RE.match(sid):
        return None, "bad_sid"
    seq, ts, version = payload.get("seq"), payload.get("ts_ms"), payload.get("v")
    if not (_is_int(seq) and 1 <= seq <= MAX_SEQ):
        return None, "bad_seq"
    if not (_is_int(ts) and ts >= 0):
        return None, "bad_ts"
    if version != 1 or isinstance(version, bool):
        return None, "bad_version"

    fields = {"sid": sid, "seq": seq, "kind": kind, "ts_ms": ts}
    if kind == "heartbeat":
        for key in ("dropped_queue", "dropped_send", "etw_restarts"):
            val = payload.get(key)
            if not (_is_int(val) and val >= 0):
                return None, "bad_heartbeat"
            fields[key] = val
        alive = payload.get("etw_alive")
        if not isinstance(alive, bool):
            return None, "bad_heartbeat"
        fields["etw_alive"] = alive
    pid = payload.get("pid")
    if pid is not None:
        if not (_is_int(pid) and 0 <= pid <= 2 ** 32):
            return None, "bad_pid"
        fields["pid"] = pid

    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return None, "too_large"
    fields["payload"] = text
    return fields, None


def parse_rfc3339(s):
    """Cloud Logging 의 UTC 시각 문자열(나노초 포함)을 datetime 으로 바꾼다. 실패하면 None."""
    if not isinstance(s, str):
        return None
    m = RFC3339_RE.match(s)
    if not m:
        return None
    frac = (m.group(2) or ".0")[1:7].ljust(6, "0")
    try:
        return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def process_entry(entry):
    """LogEntry 를 BigQuery 행으로 바꾼다. 반환: (행, insertId, None) 또는 (None, None, 사유 코드)."""
    if not isinstance(entry, dict):
        return None, None, "bad_entry"
    fields, reason = validate_event(entry.get("jsonPayload"))
    if fields is None:
        return None, None, reason
    recv = (
        parse_rfc3339(entry.get("receiveTimestamp"))
        or parse_rfc3339(entry.get("timestamp"))
        or datetime.now(timezone.utc)
    )
    severity = entry.get("severity")
    row = dict(fields)
    row["recv_time"] = recv.isoformat()
    row["severity"] = severity if severity in SEVERITIES else "DEFAULT"
    insert_id = entry.get("insertId")
    if not isinstance(insert_id, str) or not 0 < len(insert_id) <= 128:
        insert_id = None
    return row, insert_id, None


def realtime_alerts(row):
    """적재한 행에서 즉시 알릴 조건을 찾는다. 반환: [(사유, 상세)]"""
    alerts = []
    if row["kind"] == "etw_stopped":
        alerts.append(("etw_stopped", "ETW 커널 세션이 외부 요인으로 중지됨"))
    if row["kind"] == "heartbeat" and row.get("etw_alive") is False:
        alerts.append(("etw_not_alive", "heartbeat 에 etw_alive=false"))
    return alerts


def evaluate_session(s, now, hb_secs, grace_secs=GAP_GRACE_SECS):
    """세션 상태(SESSION_SQL 한 행)에서 heartbeat 공백과 seq 공백을 판정한다."""
    last_start = s.get("last_start")
    if last_start is None:
        return []
    last_stop = s.get("last_stop")
    if last_stop is not None and last_stop >= last_start:
        return []  # 정상 종료한 세션
    alerts = []
    last_hb = s.get("last_hb")
    silence = (now - (last_hb or last_start)).total_seconds()
    if silence > 3 * hb_secs:
        alerts.append(
            ("heartbeat_silence", f"heartbeat 없음 {int(silence)}초 (기준 {3 * hb_secs}초)")
        )
    hb_seq, received = s.get("hb_seq"), s.get("received_le_hb")
    if (
        last_hb is not None
        and hb_seq is not None
        and received is not None
        and (now - last_hb).total_seconds() >= grace_secs
    ):
        dropped = (s.get("dropped_queue") or 0) + (s.get("dropped_send") or 0)
        unexplained = hb_seq - received - dropped
        if unexplained > 0:
            alerts.append(("seq_gap", f"설명되지 않는 누락 {unexplained}건"))
    return alerts


def _clean(text, limit=300):
    """마크다운·멘션에 쓰이는 문자를 제거한다."""
    return re.sub(r"[`*_~|>@#<\\]", "", str(text))[:limit]


def format_alert(sid, reason, detail):
    return f"[EDR] {reason} | sid={sid or 'unknown'} | {_clean(detail)}"


# ---------------------------------------------------------------- Discord
def send_discord(text):
    """True: 전송됨, False: 실패, None: 웹훅 미설정. 웹훅 주소는 로그에 남기지 않는다."""
    url = (os.environ.get("DISCORD_WEBHOOK_URL") or "").strip()  # 비밀 값 끝의 개행 제거
    if not url:
        log.warning("DISCORD_WEBHOOK_URL 미설정: 경보 전송 생략")
        return None
    body = json.dumps({"content": text[:1900], "allowed_mentions": {"parse": []}}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "edr-lite-monitor/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError) as e:
        log.warning("Discord 전송 실패: %s", type(e).__name__)
        return False


# ---------------------------------------------------------------- BigQuery
def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bq():
    from google.cloud import bigquery  # 지연 임포트: 단위 테스트는 GCP 패키지 없이 실행

    return bigquery.Client()


def _table(client, env_name, default):
    dataset = os.environ.get("BQ_DATASET", "edr_logs")
    return f"{client.project}.{dataset}.{os.environ.get(env_name, default)}"


def _recently_alerted(client, sid, reason):
    from google.cloud import bigquery

    sql = (
        f"SELECT COUNT(*) AS n FROM `{_table(client, 'ALERTS_TABLE', 'alerts')}` "
        "WHERE alert_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @m MINUTE) "
        "AND reason = @reason AND IFNULL(sid, '') = @sid"
    )
    cfg = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("m", "INT64", _env_int("ALERT_REPEAT_MINUTES", 30)),
            bigquery.ScalarQueryParameter("reason", "STRING", reason),
            bigquery.ScalarQueryParameter("sid", "STRING", sid or ""),
        ]
    )
    return list(client.query(sql, job_config=cfg).result())[0].n > 0


def _record_alert(client, sid, reason, detail):
    errors = client.insert_rows_json(
        _table(client, "ALERTS_TABLE", "alerts"),
        [{
            "alert_time": datetime.now(timezone.utc).isoformat(),
            "sid": sid,
            "reason": reason,
            "detail": _clean(detail),
        }],
    )
    if errors:
        log.warning("경보 이력 적재 실패")


def _alert(client, sid, reason, detail):
    """같은 (sid, 사유) 경보는 ALERT_REPEAT_MINUTES 동안 한 번만 보낸다."""
    if _recently_alerted(client, sid, reason):
        return
    sent = send_discord(format_alert(sid, reason, detail))
    if sent is False:
        return  # 이력을 남기지 않아 다음 기회에 다시 시도한다
    _record_alert(client, sid, reason, detail)


def _sid_of(entry):
    payload = entry.get("jsonPayload") if isinstance(entry, dict) else None
    sid = payload.get("sid") if isinstance(payload, dict) else None
    return sid if isinstance(sid, str) and SID_RE.match(sid) else None


# ---------------------------------------------------------------- 진입점
def on_log_entry(cloud_event):
    """Pub/Sub 메시지(= LogEntry JSON) 한 건을 처리한다."""
    client = _bq()
    try:
        entry = json.loads(base64.b64decode(cloud_event.data["message"]["data"]))
    except Exception:  # 형식을 알 수 없는 메시지: 내용은 남기지 않는다
        _alert(client, None, "invalid_event", "사유 코드: bad_message")
        return
    row, insert_id, reason = process_entry(entry)
    if row is None:
        _alert(client, _sid_of(entry), "invalid_event", f"사유 코드: {reason}")
        return
    errors = client.insert_rows_json(
        _table(client, "EVENTS_TABLE", "events"),
        [row],
        row_ids=[insert_id] if insert_id else None,
    )
    if errors:
        raise RuntimeError("BigQuery 적재 실패")  # 예외로 알려 Pub/Sub 재시도에 맡긴다
    for reason, detail in realtime_alerts(row):
        _alert(client, row["sid"], reason, detail)


def watchdog(request):
    """Cloud Scheduler 호출용 HTTP 진입점."""
    from google.cloud import bigquery

    client = _bq()
    now = datetime.now(timezone.utc)
    sql = SESSION_SQL.replace("{table}", _table(client, "EVENTS_TABLE", "events"))
    cfg = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("hours", "INT64", _env_int("LOOKBACK_HOURS", 24)),
        ]
    )
    sent = 0
    for r in client.query(sql, job_config=cfg).result():
        session = dict(r.items())
        for reason, detail in evaluate_session(session, now, _env_int("HEARTBEAT_SECS", 10)):
            _alert(client, session["sid"], reason, detail)
            sent += 1
    return f"ok alerts={sent}", 200


if functions_framework is not None:
    on_log_entry = functions_framework.cloud_event(on_log_entry)
    watchdog = functions_framework.http(watchdog)
