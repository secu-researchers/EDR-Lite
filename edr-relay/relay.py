#!/usr/bin/env python3
"""edr-relay: edr-lite 에이전트의 NDJSON 이벤트를 mTLS 로 받아 GCP Cloud Logging 에 기록한다.

흐름
  에이전트 -> POST /v1/ingest (mTLS, TLS 1.3) -> 검증 -> 디스크 스풀 -> 업로더 스레드 -> Cloud Logging

원칙
  - 게스트 데이터는 신뢰할 수 없는 입력이다: 인증서 CN == 이벤트 sid 를 강제하고 형식을 검증한다.
  - 수신 핸들러는 스풀에 쓰고 바로 응답한다. GCP 장애는 스풀이 흡수한다.
  - 로그 타임스탬프는 게스트 시계가 아니라 릴레이 수신 시각이다 (에이전트 ts_ms 는 페이로드에 유지).
  - 중단 탐지: heartbeat 공백, seq 공백(드롭 카운터로 설명되지 않는 몫), etw_alive=false 를 relay_alert 로 기록한다.

사용: python relay.py --config relay.toml
"""

import argparse
import json
import os
import secrets
import ssl
import sys
import threading
import time
import tomllib
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

KINDS = {
    "agent_start", "agent_stop", "proc_start", "proc_existing", "proc_stop",
    "image_load", "net", "heartbeat", "etw_stopped", "etw_restarted",
}
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS_PER_BATCH = 5000
MAX_SEQ = 50_000_000          # seq 비트맵 메모리 상한 (약 6MiB)
UPLOAD_CHUNK = 500


def log(msg):
    print(f"[relay] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- 설정
@dataclass
class Config:
    server_cert: str
    server_key: str
    ca_cert: str
    allowed_cn_file: str
    spool_dir: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    log_name: str = "edr-lite"
    max_body_bytes: int = 4 * 1024 * 1024
    heartbeat_secs: int = 10          # 에이전트 heartbeat_secs 이상으로 맞출 것
    spool_max_files: int = 100_000
    dry_run: bool = False             # true 면 GCP 대신 stdout 으로 출력

    @staticmethod
    def load(path):
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        known = {f.name for f in fields(Config)}
        extra = set(raw) - known
        if extra:
            raise ValueError(f"알 수 없는 설정 키: {sorted(extra)}")
        cfg = Config(**raw)
        if not 1 <= cfg.heartbeat_secs <= 300:
            raise ValueError("heartbeat_secs 범위: 1~300")
        if not 1024 <= cfg.max_body_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_body_bytes 범위: 1KiB~64MiB")
        return cfg


# ---------------------------------------------------------------- 허용 CN
class AllowedCN:
    """한 줄에 CN 하나. 파일이 바뀌면 다시 읽는다 (회차 인증서 폐기 = 줄 삭제)."""

    def __init__(self, path):
        self.path = Path(path)
        self._mtime = None
        self._cns = frozenset()
        self._lock = threading.Lock()

    def contains(self, cn):
        with self._lock:
            try:
                m = self.path.stat().st_mtime_ns
            except OSError:
                self._cns, self._mtime = frozenset(), None
                return False
            if m != self._mtime:
                lines = self.path.read_text(encoding="utf-8").splitlines()
                self._cns = frozenset(
                    s for s in (ln.strip() for ln in lines) if s and not s.startswith("#")
                )
                self._mtime = m
            return cn in self._cns


# ---------------------------------------------------------------- 검증
def validate_batch(cn, body):
    """본문(NDJSON)을 검증해 이벤트 목록을 반환. 하나라도 잘못되면 ValueError."""
    lines = [ln for ln in body.split(b"\n") if ln.strip()]
    if not lines:
        raise ValueError("빈 본문")
    if len(lines) > MAX_EVENTS_PER_BATCH:
        raise ValueError("배치 이벤트 수 초과")
    events = []
    for ln in lines:
        if len(ln) > MAX_LINE_BYTES:
            raise ValueError("줄 길이 초과")
        try:
            ev = json.loads(ln)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("JSON 파싱 실패")
        if not isinstance(ev, dict):
            raise ValueError("객체가 아님")
        if ev.get("kind") not in KINDS:
            raise ValueError("알 수 없는 kind")
        if ev.get("sid") != cn:
            raise ValueError("sid 와 인증서 CN 불일치")
        seq, ts, v = ev.get("seq"), ev.get("ts_ms"), ev.get("v")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (seq, ts, v)):
            raise ValueError("v/seq/ts_ms 형식 오류")
        if not 1 <= seq <= MAX_SEQ:
            raise ValueError("seq 범위 오류")
        events.append(ev)
    return events


# ---------------------------------------------------------------- 세션 추적
class SeqSet:
    """수신한 seq 의 비트맵. 재전송(중복)을 구분해 고유 개수를 센다."""

    def __init__(self):
        self.bits = bytearray()
        self.count = 0

    def add(self, seq):
        i = seq >> 3
        if i >= len(self.bits):
            self.bits.extend(bytes(i - len(self.bits) + 1 + 1024))
        m = 1 << (seq & 7)
        if self.bits[i] & m:
            return False
        self.bits[i] |= m
        self.count += 1
        return True


class _Session:
    def __init__(self):
        self.seqs = SeqSet()
        self.last_hb = None
        self.silent = False
        self.closed = False
        self.gap_streak = 0


def _alert(sid, reason, detail):
    return {"v": 1, "kind": "relay_alert", "sid": sid, "reason": reason, "detail": detail}


def _nonneg_int(x):
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else 0


class Tracker:
    def __init__(self, hb_secs):
        self.hb_secs = hb_secs
        self._s = {}
        self._lock = threading.Lock()

    def observe(self, sid, events, now):
        """배치를 반영하고 발생한 경보 목록을 반환."""
        alerts = []
        with self._lock:
            st = self._s.setdefault(sid, _Session())
            for ev in events:
                st.seqs.add(ev["seq"])
                if ev["kind"] == "agent_start":
                    st.closed = False
                    st.silent = False
                elif ev["kind"] == "agent_stop":
                    st.closed = True
            for ev in events:
                if ev["kind"] != "heartbeat":
                    continue
                st.last_hb = now
                st.silent = False
                if ev.get("etw_alive") is False:
                    alerts.append(_alert(sid, "etw_not_alive", "heartbeat 에 etw_alive=false"))
                dropped = _nonneg_int(ev.get("dropped_queue")) + _nonneg_int(ev.get("dropped_send"))
                unexplained = ev["seq"] - st.seqs.count - dropped
                if unexplained > 0:
                    st.gap_streak += 1
                    if st.gap_streak == 2:  # 전송 중인 이벤트로 인한 일시적 차이는 무시
                        alerts.append(_alert(sid, "seq_gap", f"설명되지 않는 누락 {unexplained}건"))
                else:
                    st.gap_streak = 0
        return alerts

    def check_silence(self, now):
        alerts = []
        with self._lock:
            for sid, st in self._s.items():
                if st.closed or st.silent or st.last_hb is None:
                    continue
                if now - st.last_hb > 3 * self.hb_secs:
                    st.silent = True
                    alerts.append(_alert(sid, "heartbeat_silence", f"{3 * self.hb_secs}초 이상 heartbeat 없음"))
        return alerts


# ---------------------------------------------------------------- 엔트리/스풀
def make_entry(ev, recv_ms):
    ev = dict(ev)
    ev["recv_ts_ms"] = recv_ms
    kind, sid = ev["kind"], ev["sid"]
    if kind == "relay_alert" or "seq" not in ev:
        iid = f"relay-{sid}-{recv_ms}-{secrets.token_hex(4)}"
        sev = "ERROR"
    else:
        iid = f"{sid}-{ev['seq']}"
        sev = "INFO"
        if kind == "etw_stopped":
            sev = "ERROR"
        elif kind == "heartbeat" and ev.get("etw_alive") is False:
            sev = "WARNING"
    return {
        "severity": sev,
        "insert_id": iid,
        "labels": {"sid": sid, "kind": kind},
        "timestamp_ms": recv_ms,
        "payload": ev,
    }


class Spool:
    """디스크 큐. 배치당 파일 1개 (임시 파일 작성 후 원자적 rename)."""

    def __init__(self, directory, max_files):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_files = max_files
        self._lock = threading.Lock()
        self._count = len(list(self.dir.glob("*.ndjson")))

    def put(self, entries):
        with self._lock:
            if self._count >= self.max_files:
                return False
            token = secrets.token_hex(4)
            tmp = self.dir / f".tmp-{token}"
            data = "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.dir / f"{time.time_ns():020d}-{token}.ndjson")
            self._count += 1
            return True

    def oldest(self):
        files = sorted(self.dir.glob("*.ndjson"))
        return files[0] if files else None

    def remove(self, path):
        with self._lock:
            path.unlink(missing_ok=True)
            self._count = max(0, self._count - 1)


# ---------------------------------------------------------------- 싱크
class StdoutSink:
    def write(self, entries):
        for e in entries:
            print(json.dumps(e, ensure_ascii=False), flush=True)


class GcpSink:
    def __init__(self, log_name):
        from google.cloud import logging as gcl
        from google.cloud.logging_v2.resource import Resource

        client = gcl.Client()  # GOOGLE_APPLICATION_CREDENTIALS 의 서비스 계정 사용
        self.logger = client.logger(log_name)
        self.resource = Resource(type="global", labels={"project_id": client.project})

    def write(self, entries):
        for i in range(0, len(entries), UPLOAD_CHUNK):
            batch = self.logger.batch()
            for e in entries[i:i + UPLOAD_CHUNK]:
                batch.log_struct(
                    e["payload"],
                    resource=self.resource,
                    severity=e["severity"],
                    insert_id=e["insert_id"],
                    labels=e["labels"],
                    timestamp=datetime.fromtimestamp(e["timestamp_ms"] / 1000, timezone.utc),
                )
            batch.commit()


def run_uploader(spool, sink, stop):
    backoff = 1
    while not stop.is_set():
        path = spool.oldest()
        if path is None:
            stop.wait(0.5)
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            sink.write([json.loads(ln) for ln in lines if ln])
            spool.remove(path)
            backoff = 1
        except Exception as e:  # 네트워크/권한 오류 포함: 스풀을 유지하고 재시도
            log(f"업로드 실패 ({path.name}): {e}")
            stop.wait(backoff)
            backoff = min(backoff * 2, 60)


# ---------------------------------------------------------------- 앱/HTTP
class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.allowed = AllowedCN(cfg.allowed_cn_file)
        self.spool = Spool(cfg.spool_dir, cfg.spool_max_files)
        self.tracker = Tracker(cfg.heartbeat_secs)

    def ingest(self, cn, body):
        try:
            events = validate_batch(cn, body)
        except ValueError as e:
            log(f"거부 cn={cn}: {e}")
            return 400
        recv_ms = int(time.time() * 1000)
        alerts = self.tracker.observe(cn, events, time.monotonic())
        entries = [make_entry(ev, recv_ms) for ev in events]
        entries += [make_entry(a, recv_ms) for a in alerts]
        return 200 if self.spool.put(entries) else 503

    def emit_alerts(self, alerts):
        if alerts:
            recv_ms = int(time.time() * 1000)
            self.spool.put([make_entry(a, recv_ms) for a in alerts])


def peer_cn(sock):
    cert = sock.getpeercert()
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 15
    server_version = "edr-relay"

    def setup(self):
        super().setup()
        self.connection.do_handshake()  # 핸드셰이크를 요청 스레드에서 수행 (accept 루프 보호)

    def log_message(self, fmt, *args):
        log(f"{self.client_address[0]} {fmt % args}")

    def _reply(self, code):
        if code >= 400:
            self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        app = self.server.app
        cn = peer_cn(self.connection)
        if cn is None or not app.allowed.contains(cn):
            return self._reply(403)
        if self.path != "/v1/ingest":
            return self._reply(404)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(411)
        if length <= 0:
            return self._reply(400)
        if length > app.cfg.max_body_bytes:
            return self._reply(413)
        body = self.rfile.read(length)
        if len(body) != length:
            return self._reply(400)
        self._reply(app.ingest(cn, body))

    def do_GET(self):
        self._reply(405)


def build_ssl_context(cfg):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cfg.server_cert, cfg.server_key)
    ctx.load_verify_locations(cfg.ca_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED  # 클라이언트 인증서 필수
    return ctx


def run_watchdog(app, stop):
    while not stop.wait(5):
        app.emit_alerts(app.tracker.check_silence(time.monotonic()))


def main():
    ap = argparse.ArgumentParser(description="edr-relay")
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    cfg = Config.load(args.config)
    app = App(cfg)
    stop = threading.Event()

    sink = StdoutSink() if cfg.dry_run else GcpSink(cfg.log_name)
    threading.Thread(target=run_uploader, args=(app.spool, sink, stop), name="uploader", daemon=True).start()
    threading.Thread(target=run_watchdog, args=(app, stop), name="watchdog", daemon=True).start()

    srv = ThreadingHTTPServer((cfg.listen_host, cfg.listen_port), Handler)
    srv.daemon_threads = True
    srv.app = app
    srv.socket = build_ssl_context(cfg).wrap_socket(
        srv.socket, server_side=True, do_handshake_on_connect=False
    )
    log(f"수신 대기 {cfg.listen_host}:{cfg.listen_port} (dry_run={cfg.dry_run})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


if __name__ == "__main__":
    main()
