-- edr-lite 감시용 BigQuery 스키마.
-- <PROJECT_ID>, <LOCATION> 은 실제 값으로 바꿔서 BigQuery 콘솔의 쿼리 편집기에서 실행한다.
-- 두 테이블은 Function(on_log_entry, watchdog)이 실행되기 전에 만들어져 있어야 한다.

CREATE SCHEMA IF NOT EXISTS `<PROJECT_ID>.edr_logs`
OPTIONS (
  location = '<LOCATION>',
  default_partition_expiration_days = 30
);

-- 검증을 통과한 에이전트 이벤트. 분석에 자주 쓰는 값만 열로 두고 나머지는 payload(JSON)에 둔다.
CREATE TABLE IF NOT EXISTS `<PROJECT_ID>.edr_logs.events` (
  recv_time     TIMESTAMP NOT NULL,   -- Cloud Logging 수신 시각 (게스트 시계가 아님)
  sid           STRING    NOT NULL,   -- 분석 회차 ID
  seq           INT64     NOT NULL,   -- 에이전트가 부여한 순번 (재시작하면 1부터 다시 시작)
  kind          STRING    NOT NULL,
  ts_ms         INT64,                -- 게스트 시계 기준 시각 (신뢰하지 않음)
  severity      STRING,
  pid           INT64,
  dropped_queue INT64,                -- heartbeat 전용
  dropped_send  INT64,                -- heartbeat 전용
  etw_alive     BOOL,                 -- heartbeat 전용
  etw_restarts  INT64,                -- heartbeat 전용
  payload       JSON
)
PARTITION BY DATE(recv_time)
CLUSTER BY sid, kind
OPTIONS (
  partition_expiration_days = 30
);

-- Function 이 보낸 경보 이력. 같은 경보를 반복해서 보내지 않기 위한 기준으로도 쓴다.
CREATE TABLE IF NOT EXISTS `<PROJECT_ID>.edr_logs.alerts` (
  alert_time TIMESTAMP NOT NULL,
  sid        STRING,
  reason     STRING NOT NULL,
  detail     STRING
)
PARTITION BY DATE(alert_time)
OPTIONS (
  partition_expiration_days = 30
);
