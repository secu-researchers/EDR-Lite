//! 설정 파일 (TOML) 로드 및 검증.
//! 보안상 위험한 설정(평문 http, 핀 미설정 등)은 아예 허용하지 않는다.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// 릴레이 수집 엔드포인트. 반드시 https. 예: "https://10.30.0.10:8443/v1/ingest"
    pub relay_url: String,
    /// 이번 분석 회차 ID (릴레이가 인증서 CN 과 대조)
    pub session_id: String,
    /// 릴레이 서버 인증서를 서명한 사설 CA (PEM). 시스템 루트 저장소는 사용하지 않는다.
    pub ca_cert: PathBuf,
    /// 이번 회차용 클라이언트 인증서/키 (PEM)
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    /// 릴레이 서버 리프 인증서(DER)의 SHA-256 (hex 64자). 사설 CA 가 탈취돼도 MITM 방지.
    pub server_cert_sha256: String,

    #[serde(default = "d_batch_max")]
    pub batch_max_events: usize,
    #[serde(default = "d_batch_bytes")]
    pub batch_max_bytes: usize,
    #[serde(default = "d_flush_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "d_queue")]
    pub queue_capacity: usize,
    #[serde(default = "d_hb")]
    pub heartbeat_secs: u64,
    #[serde(default = "d_true")]
    pub collect_image_loads: bool,
    #[serde(default = "d_true")]
    pub collect_network: bool,

    /// ETW 커널 세션 이름. 생략 시 회차마다 평범한 이름을 무작위로 생성한다
    /// (`logman query -ets` 에 고정 문자열로 노출되지 않도록).
    #[serde(default)]
    pub trace_name: Option<String>,
    /// true 면 TLS 로딩 직후 client_key 파일을 덮어쓰고 삭제한다.
    /// 키는 이미 메모리에 올라가 있어 동작에는 지장이 없고, 디스크에서 훔쳐갈 키가 사라진다.
    /// (스냅샷 복원형 워크플로 전제: 재시작하려면 키를 다시 배치)
    #[serde(default)]
    pub wipe_client_key: bool,
}

fn d_batch_max() -> usize { 500 }
fn d_batch_bytes() -> usize { 512 * 1024 }
fn d_flush_ms() -> u64 { 500 }
fn d_queue() -> usize { 50_000 }
fn d_hb() -> u64 { 10 }
fn d_true() -> bool { true }

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("설정 파일을 읽을 수 없음 {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| format!("설정 파싱 실패: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.relay_url.starts_with("https://") {
            return Err("relay_url 은 https:// 로 시작해야 합니다".into());
        }
        if self.session_id.is_empty()
            || self.session_id.len() > 64
            || !self
                .session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("session_id 는 1~64자 [A-Za-z0-9_-] 이어야 합니다".into());
        }
        pin_bytes(&self.server_cert_sha256)?;
        if !(1..=5000).contains(&self.batch_max_events) {
            return Err("batch_max_events 범위: 1~5000".into());
        }
        if !(4096..=4 * 1024 * 1024).contains(&self.batch_max_bytes) {
            return Err("batch_max_bytes 범위: 4KiB~4MiB".into());
        }
        if !(100..=60_000).contains(&self.flush_interval_ms) {
            return Err("flush_interval_ms 범위: 100~60000".into());
        }
        if !(100..=1_000_000).contains(&self.queue_capacity) {
            return Err("queue_capacity 범위: 100~1000000".into());
        }
        if !(1..=300).contains(&self.heartbeat_secs) {
            return Err("heartbeat_secs 범위: 1~300".into());
        }
        if let Some(tn) = &self.trace_name {
            if tn.is_empty()
                || tn.len() > 128
                || !tn.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
            {
                return Err("trace_name 은 1~128자 [A-Za-z0-9 _-] 이어야 합니다".into());
            }
        }
        Ok(())
    }
}

/// hex 문자열 → 32바이트. ':' 구분자 허용 (openssl 출력 형식).
pub fn pin_bytes(hex: &str) -> Result<[u8; 32], String> {
    let cleaned: String = hex.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    if cleaned.len() != 64 {
        return Err("server_cert_sha256 은 SHA-256 hex 64자여야 합니다".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "잘못된 hex")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "server_cert_sha256 hex 형식 오류")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        toml::from_str(
            r#"
relay_url = "https://10.30.0.10:8443/v1/ingest"
session_id = "run-20261018-001"
ca_cert = "ca.pem"
client_cert = "agent.pem"
client_key = "agent.key"
server_cert_sha256 = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
"#,
        )
        .unwrap()
    }

    #[test]
    fn valid_config() {
        base().validate().unwrap();
    }

    #[test]
    fn rejects_http_and_bad_pin_and_unknown_fields() {
        let mut c = base();
        c.relay_url = "http://10.30.0.10/".into();
        assert!(c.validate().is_err());

        let mut c = base();
        c.server_cert_sha256 = "abcd".into();
        assert!(c.validate().is_err());

        let mut c = base();
        c.session_id = "bad id;rm".into();
        assert!(c.validate().is_err());

        let r: Result<Config, _> = toml::from_str("relay_url='https://x'\nproxy='http://evil'");
        assert!(r.is_err());
    }
}
