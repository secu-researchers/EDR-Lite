//! Google OAuth2: 서비스 계정 키로 JWT 를 서명해 접근 토큰을 받는다 (JWT bearer 방식).
//! - 키는 메모리에만 보관한다 (파일은 로드 직후 main 이 선택적으로 삭제)
//! - 토큰 엔드포인트는 https://oauth2.googleapis.com/ 만 허용한다
//! - 토큰·JWT·개인키는 오류 메시지에 포함하지 않는다

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCOPE: &str = "https://www.googleapis.com/auth/logging.write";
const TOKEN_URI_PREFIX: &str = "https://oauth2.googleapis.com/";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// 만료 이 시간 전에 미리 갱신한다
const REFRESH_MARGIN_SECS: u64 = 120;

#[derive(Deserialize)]
struct KeyFile {
    #[serde(rename = "type")]
    kind: String,
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

pub struct TokenProvider {
    agent: ureq::Agent,
    email: String,
    key_id: Option<String>,
    key: RsaKeyPair,
    token_uri: String,
    cached: Option<(String, Instant)>,
}

impl TokenProvider {
    pub fn from_key_file(agent: ureq::Agent, path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("서비스 계정 키를 읽을 수 없음 {}: {e}", path.display()))?;
        Self::from_key_json(agent, &text)
    }

    pub fn from_key_json(agent: ureq::Agent, json: &str) -> Result<Self, String> {
        let kf: KeyFile =
            serde_json::from_str(json).map_err(|e| format!("서비스 계정 키 JSON 형식 오류: {e}"))?;
        if kf.kind != "service_account" {
            return Err("서비스 계정 키(type=service_account)가 아닙니다".into());
        }
        let token_uri = kf.token_uri.unwrap_or_else(|| DEFAULT_TOKEN_URI.to_string());
        if !token_uri.starts_with(TOKEN_URI_PREFIX) {
            return Err("token_uri 는 https://oauth2.googleapis.com/ 이어야 합니다".into());
        }
        let key = parse_rsa_key(&kf.private_key)?;
        Ok(TokenProvider {
            agent,
            email: kf.client_email,
            key_id: kf.private_key_id,
            key,
            token_uri,
            cached: None,
        })
    }

    /// 유효한 접근 토큰을 반환한다. 만료가 가까우면 새로 받는다.
    pub fn token(&mut self) -> Result<String, String> {
        if let Some((tok, refresh_at)) = &self.cached {
            if Instant::now() < *refresh_at {
                return Ok(tok.clone());
            }
        }
        let jwt = self.make_jwt()?;
        let resp = self.agent.post(&self.token_uri).send_form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt.as_str()),
        ]);
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                return Err(format!("토큰 발급 실패 HTTP {code}: {}", read_limited(r)));
            }
            Err(e) => return Err(format!("토큰 요청 오류: {e}")),
        };
        let parsed: TokenResponse = serde_json::from_str(&read_limited(resp))
            .map_err(|_| "토큰 응답 형식 오류".to_string())?;
        let ttl = parsed.expires_in.unwrap_or(3600);
        let usable = ttl.saturating_sub(REFRESH_MARGIN_SECS).max(30);
        self.cached = Some((
            parsed.access_token.clone(),
            Instant::now() + Duration::from_secs(usable),
        ));
        Ok(parsed.access_token)
    }

    /// 서버가 401 을 돌려줬을 때 캐시를 버려 다음 호출에서 새로 받게 한다.
    pub fn invalidate(&mut self) {
        self.cached = None;
    }

    fn make_jwt(&self) -> Result<String, String> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let input = signing_input(&self.email, self.key_id.as_deref(), &self.token_uri, iat);
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig)
            .map_err(|_| "JWT 서명 실패".to_string())?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
}

/// 응답 본문을 최대 4KiB 만 읽는다 (진단용). 토큰 응답 파싱에도 쓴다.
pub fn read_limited(resp: ureq::Response) -> String {
    let mut s = String::new();
    let _ = resp.into_reader().take(4096).read_to_string(&mut s);
    s
}

fn signing_input(email: &str, key_id: Option<&str>, aud: &str, iat: u64) -> String {
    let header = match key_id {
        Some(kid) => serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid}),
        None => serde_json::json!({"alg": "RS256", "typ": "JWT"}),
    };
    let claims = serde_json::json!({
        "iss": email,
        "scope": SCOPE,
        "aud": aud,
        "iat": iat,
        "exp": iat + 3600,
    });
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn parse_rsa_key(pem: &str) -> Result<RsaKeyPair, String> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::pkcs8_private_keys(&mut rd)
        .next()
        .ok_or_else(|| "private_key 에 PKCS#8 개인키가 없음".to_string())?
        .map_err(|e| format!("private_key PEM 파싱 실패: {e}"))?;
    RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()).map_err(|_| "RSA 개인키 형식 오류".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new().build()
    }

    fn decode(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn signing_input_has_expected_header_and_claims() {
        let s = signing_input("sa@p.iam.gserviceaccount.com", Some("k1"), DEFAULT_TOKEN_URI, 1000);
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 2);
        let h = decode(parts[0]);
        assert_eq!(h["alg"], "RS256");
        assert_eq!(h["kid"], "k1");
        let c = decode(parts[1]);
        assert_eq!(c["iss"], "sa@p.iam.gserviceaccount.com");
        assert_eq!(c["scope"], SCOPE);
        assert_eq!(c["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(c["exp"].as_u64().unwrap(), 4600);
    }

    #[test]
    fn rejects_non_service_account_and_foreign_token_uri() {
        let r = TokenProvider::from_key_json(
            agent(),
            r#"{"type":"authorized_user","client_email":"a","private_key":"x"}"#,
        );
        assert!(r.is_err());
        let r = TokenProvider::from_key_json(
            agent(),
            r#"{"type":"service_account","client_email":"a","private_key":"x","token_uri":"https://evil.example/token"}"#,
        );
        assert!(r.err().unwrap().contains("token_uri"));
    }

    #[test]
    fn rejects_malformed_json_and_bad_private_key() {
        assert!(TokenProvider::from_key_json(agent(), "not json").is_err());
        let r = TokenProvider::from_key_json(
            agent(),
            r#"{"type":"service_account","client_email":"a","private_key":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}"#,
        );
        assert!(r.is_err());
    }
}
