//! mTLS 클라이언트 설정.
//! - TLS 1.3 전용
//! - 신뢰 루트: 설정에 지정한 사설 CA 하나뿐 (OS 인증서 저장소 미사용 → 악성코드가
//!   게스트에 루트 CA 를 심어도 무의미)
//! - 추가로 서버 리프 인증서 SHA-256 핀 검사 (CA 키 유출 시에도 MITM 차단)

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1) 체인/이름/유효기간 검증 (사설 CA 기준)
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        // 2) 리프 인증서 핀 검사
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() != self.pin {
            return Err(rustls::Error::General(
                "서버 인증서 핀 불일치 (MITM 의심)".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("{} 열기 실패: {e}", path.display()))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut BufReader::new(f)).collect();
    let certs = certs.map_err(|e| format!("{} PEM 파싱 실패: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} 에 인증서가 없음", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("{} 열기 실패: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(f))
        .map_err(|e| format!("{} 키 파싱 실패: {e}", path.display()))?
        .ok_or_else(|| format!("{} 에 개인키가 없음", path.display()))
}

pub fn client_config(
    ca: &Path,
    cert: &Path,
    key: &Path,
    pin: [u8; 32],
) -> Result<Arc<ClientConfig>, String> {
    let provider: Arc<CryptoProvider> = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c).map_err(|e| format!("CA 추가 실패: {e}"))?;
    }
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("검증기 생성 실패: {e}"))?;

    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 버전 설정 실패: {e}"))?
        .dangerous() // 커스텀 검증기 사용 (기본 검증 + 핀, 검증을 약화시키지 않음)
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { inner, pin }))
        .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| format!("클라이언트 인증서 설정 실패: {e}"))?;
    Ok(Arc::new(cfg))
}
