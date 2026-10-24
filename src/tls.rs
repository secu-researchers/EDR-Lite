//! TLS 클라이언트 설정.
//! - TLS 1.3 전용
//! - 신뢰 루트: 에이전트에 내장된 공개 루트 CA 목록(webpki-roots)뿐. OS 인증서 저장소는
//!   쓰지 않는다 → 악성코드가 게스트에 루트 CA 를 심어도 Google 연결을 가로챌 수 없다.
//! - 클라이언트 인증서는 쓰지 않는다 (인증은 서비스 계정 접근 토큰으로 한다)

use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

pub fn client_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 버전 설정 실패: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tls13_config_with_builtin_roots() {
        let cfg = client_config().unwrap();
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        // 클라이언트 인증서를 제시하지 않는다
        assert!(!cfg.client_auth_cert_resolver.has_certs());
    }
}
