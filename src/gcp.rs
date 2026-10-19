//! Google Cloud Logging 직접 전송 (entries.write REST).
//! - 단방향: 응답 본문은 오류 진단 외에는 해석하지 않는다 (명령 수신 기능 없음)
//! - 프록시 환경변수 미사용, 리다이렉트 금지
//! - 인증: 서비스 계정 접근 토큰 (auth.rs). 401 이면 토큰을 새로 받아 한 번만 재시도한다
//! - 로그 시각은 서버 수신 시각에 맡기고, 게스트 시각(ts_ms)은 페이로드에 그대로 둔다

use crate::auth::{read_limited, TokenProvider};
use crate::sender::Transport;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const WRITE_URL: &str = "https://logging.googleapis.com/v2/entries:write";

pub fn http_agent(tls: Arc<rustls::ClientConfig>) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .tls_config(tls)
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("edr-lite/", env!("CARGO_PKG_VERSION")))
        .build()
}

pub struct GcpTransport {
    agent: ureq::Agent,
    auth: TokenProvider,
    project_id: String,
    log_name: String,
}

impl GcpTransport {
    pub fn new(
        agent: ureq::Agent,
        project_id: &str,
        log_name: &str,
        key_path: &Path,
    ) -> Result<Self, String> {
        let auth = TokenProvider::from_key_file(agent.clone(), key_path)?;
        Ok(GcpTransport {
            agent,
            auth,
            project_id: project_id.to_string(),
            log_name: log_name.to_string(),
        })
    }
}

impl Transport for GcpTransport {
    fn send(&mut self, body: &[u8]) -> Result<(), String> {
        let req = build_request(&self.project_id, &self.log_name, body)?;
        let payload = serde_json::to_vec(&req).map_err(|e| format!("요청 직렬화 실패: {e}"))?;
        for attempt in 0..2 {
            let token = self.auth.token()?;
            let result = self
                .agent
                .post(WRITE_URL)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_bytes(&payload);
            match result {
                Ok(resp) => {
                    // 연결 재사용을 위해 소량만 읽고 버린다. 내용은 해석하지 않음.
                    let mut sink = Vec::new();
                    let _ = resp.into_reader().take(1024).read_to_end(&mut sink);
                    return Ok(());
                }
                Err(ureq::Error::Status(401, _)) if attempt == 0 => self.auth.invalidate(),
                Err(ureq::Error::Status(code, resp)) => {
                    return Err(format!("Cloud Logging HTTP {code}: {}", read_limited(resp)));
                }
                Err(e) => return Err(format!("전송 오류: {e}")),
            }
        }
        Err("인증 실패 (토큰을 갱신한 뒤에도 401)".into())
    }
}

fn severity(ev: &Value) -> &'static str {
    match ev.get("kind").and_then(Value::as_str) {
        Some("etw_stopped") => "ERROR",
        Some("heartbeat") if ev.get("etw_alive").and_then(Value::as_bool) == Some(false) => "WARNING",
        _ => "INFO",
    }
}

/// NDJSON 배치를 entries.write 요청 본문으로 변환한다.
/// logName/resource 는 요청 공통값으로 두고, 항목마다 jsonPayload·severity·insertId·labels 를 붙인다.
pub fn build_request(project_id: &str, log_name: &str, ndjson: &[u8]) -> Result<Value, String> {
    let mut entries = Vec::new();
    for line in ndjson.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let ev: Value =
            serde_json::from_slice(line).map_err(|e| format!("이벤트 JSON 오류: {e}"))?;
        let sid = ev.get("sid").and_then(Value::as_str).unwrap_or("unknown").to_string();
        let kind = ev.get("kind").and_then(Value::as_str).unwrap_or("unknown").to_string();
        let seq = ev.get("seq").and_then(Value::as_u64);
        let mut entry = json!({
            "jsonPayload": ev,
            "severity": severity(&ev),
            "labels": { "sid": sid, "kind": kind },
        });
        if let Some(seq) = seq {
            entry["insertId"] = json!(format!("{sid}-{seq}"));
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("빈 배치".into());
    }
    Ok(json!({
        "logName": format!("projects/{project_id}/logs/{log_name}"),
        "resource": { "type": "global", "labels": { "project_id": project_id } },
        "entries": entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_entries_with_labels_insert_id_and_severity() {
        let body = concat!(
            r#"{"v":1,"sid":"run-1","seq":1,"ts_ms":5,"kind":"proc_start","pid":4}"#, "\n",
            r#"{"v":1,"sid":"run-1","seq":2,"ts_ms":6,"kind":"etw_stopped","count":1,"detail":"x"}"#, "\n",
            r#"{"v":1,"sid":"run-1","seq":3,"ts_ms":7,"kind":"heartbeat","etw_alive":false}"#, "\n",
        );
        let req = build_request("edr-lab-123456", "lab_malware", body.as_bytes()).unwrap();
        assert_eq!(req["logName"], "projects/edr-lab-123456/logs/lab_malware");
        assert_eq!(req["resource"]["type"], "global");
        assert_eq!(req["resource"]["labels"]["project_id"], "edr-lab-123456");
        let e = req["entries"].as_array().unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0]["insertId"], "run-1-1");
        assert_eq!(e[0]["severity"], "INFO");
        assert_eq!(e[0]["labels"]["kind"], "proc_start");
        assert_eq!(e[0]["jsonPayload"]["pid"], 4);
        assert_eq!(e[1]["severity"], "ERROR");
        assert_eq!(e[2]["severity"], "WARNING");
        // 게스트 시각은 페이로드에 유지되고 entry 의 timestamp 는 지정하지 않는다
        assert_eq!(e[0]["jsonPayload"]["ts_ms"], 5);
        assert!(e[0].get("timestamp").is_none());
    }

    #[test]
    fn rejects_invalid_or_empty_batches() {
        assert!(build_request("p", "l", b"not json\n").is_err());
        assert!(build_request("p", "l", b"\n\n").is_err());
    }

    #[test]
    fn healthy_heartbeat_is_info() {
        let body = br#"{"v":1,"sid":"s","seq":9,"ts_ms":1,"kind":"heartbeat","etw_alive":true}"#;
        let req = build_request("p", "l", body).unwrap();
        assert_eq!(req["entries"][0]["severity"], "INFO");
    }
}
