//! 설정 파일 (TOML) 로드 및 검증.
//! 보안상 위험한 설정(형식이 잘못된 프로젝트 ID, 허용되지 않은 문자 등)은 아예 허용하지 않는다.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// 로그를 기록할 GCP 프로젝트 ID (EDR 전용 프로젝트)
    pub gcp_project_id: String,
    /// Logs Writer 역할만 가진 서비스 계정 키(JSON) 경로
    pub sa_key_path: PathBuf,
    /// 이번 분석 회차 ID (모든 이벤트의 sid)
    pub session_id: String,

    /// Cloud Logging 로그 이름(log_id)
    #[serde(default = "d_log_name")]
    pub log_name: String,
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
    /// true 면 서비스 계정 키를 메모리에 올린 직후 키 파일을 덮어쓰고 삭제한다.
    /// 키는 이미 메모리에 있어 동작에는 지장이 없고, 디스크에서 훔쳐갈 키가 사라진다.
    /// (스냅샷 복원형 워크플로 전제: 재시작하려면 키를 다시 배치)
    #[serde(default)]
    pub wipe_sa_key: bool,
}

fn d_log_name() -> String { "lab_malware".into() }
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
        if !valid_project_id(&self.gcp_project_id) {
            return Err("gcp_project_id 는 6~30자, 소문자로 시작, [a-z0-9-], 하이픈으로 끝날 수 없습니다".into());
        }
        if self.log_name.is_empty()
            || self.log_name.len() > 100
            || !self
                .log_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err("log_name 은 1~100자 [A-Za-z0-9._-] 이어야 합니다".into());
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
        if !(1..=1000).contains(&self.batch_max_events) {
            return Err("batch_max_events 범위: 1~1000".into());
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

/// GCP 프로젝트 ID 형식: 6~30자, 소문자로 시작, 소문자·숫자·하이픈, 하이픈으로 끝나지 않음.
fn valid_project_id(s: &str) -> bool {
    let b = s.as_bytes();
    (6..=30).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[b.len() - 1] != b'-'
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        toml::from_str(
            r#"
gcp_project_id = "edr-lab-123456"
sa_key_path = "sa-key.json"
session_id = "run-20261018-001"
"#,
        )
        .unwrap()
    }

    #[test]
    fn valid_config_and_defaults() {
        let c = base();
        c.validate().unwrap();
        assert_eq!(c.log_name, "lab_malware");
        assert!(!c.wipe_sa_key);
    }

    #[test]
    fn rejects_bad_project_id() {
        for bad in ["Edr-Lab-1", "short", "1edr-lab-123", "edr-lab-123-", "edr_lab_123", ""] {
            let mut c = base();
            c.gcp_project_id = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_bad_names_and_ranges() {
        let mut c = base();
        c.log_name = "a/b".into();
        assert!(c.validate().is_err());

        let mut c = base();
        c.session_id = "bad id;rm".into();
        assert!(c.validate().is_err());

        let mut c = base();
        c.batch_max_events = 1001;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_unknown_and_removed_fields() {
        let r: Result<Config, _> = toml::from_str(
            "gcp_project_id='edr-lab-123456'\nsa_key_path='k.json'\nsession_id='s'\nproxy='http://evil'",
        );
        assert!(r.is_err());
        let r: Result<Config, _> = toml::from_str(
            "gcp_project_id='edr-lab-123456'\nsa_key_path='k.json'\nsession_id='s'\nrelay_url='https://x'",
        );
        assert!(r.is_err());
    }
}
