//! 이벤트 스키마와 Emitter(이벤트 큐 투입부).
//!
//! ETW 콜백 스레드는 절대 블로킹되면 안 되므로, Emitter 는 bounded 채널에
//! `try_send` 만 하고 큐가 가득 차면 드롭 카운터만 올린다.
//! 시퀀스 번호는 "생성 시점"에 부여하므로, 릴레이는
//!   (seq 공백) - (heartbeat 의 dropped 카운터) != 0  → 변조/중단 의심
//! 으로 판단할 수 있다.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u8 = 1;

/// 필드 길이 상한 (문자 수). 공격자가 조절 가능한 값이므로 반드시 자른다.
pub const MAX_IMAGE: usize = 1024;
pub const MAX_CMDLINE: usize = 8192;
pub const MAX_PATH: usize = 1024;

#[derive(Debug, Serialize, Clone)]
pub struct Envelope {
    pub v: u8,
    /// 분석 세션 ID. 릴레이는 이 값을 믿지 말고 클라이언트 인증서 신원과 대조해야 한다.
    pub sid: Arc<str>,
    pub seq: u64,
    /// 에이전트 수집 시각 (Unix epoch ms, UTC)
    pub ts_ms: u64,
    #[serde(flatten)]
    pub body: EventBody,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventBody {
    AgentStart {
        version: &'static str,
        agent_pid: u32,
    },
    AgentStop {
        reason: String,
    },
    /// ETW 커널 세션의 process() 가 반환됨 = 세션이 외부 요인으로 중지됨.
    /// 샘플이 `logman stop ... -ets` 등으로 수집을 끄면 여기서 잡힌다.
    EtwStopped {
        /// 이번이 몇 번째 중지인지 (1부터)
        count: u32,
        detail: String,
    },
    /// 자동 재시작 성공
    EtwRestarted {
        count: u32,
    },
    /// 새 프로세스 생성
    ProcStart {
        pid: u32,
        ppid: u32,
        session: u32,
        image: String,
        cmdline: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_sid: Option<String>,
    },
    /// 에이전트 시작 시점에 이미 실행 중이던 프로세스 (ETW rundown)
    ProcExisting {
        pid: u32,
        ppid: u32,
        image: String,
        cmdline: String,
    },
    ProcStop {
        pid: u32,
        ppid: u32,
        exit_code: u32,
        image: String,
    },
    ImageLoad {
        pid: u32,
        path: String,
    },
    Net {
        pid: u32,
        proto: &'static str,
        /// "connect" | "accept" | "send"
        op: &'static str,
        src: String,
        sport: u16,
        dst: String,
        dport: u16,
    },
    Heartbeat {
        uptime_s: u64,
        emitted: u64,
        dropped_queue: u64,
        dropped_send: u64,
        parse_errors: u64,
        /// ETW 커널 세션이 현재 살아있는가. false 면 수집이 멈춘 상태.
        etw_alive: bool,
        /// 마지막 커널 이벤트 수신 이후 경과 시간(초). 정상 Windows 는 보통 수초 내.
        /// 값이 계속 커지면 세션은 살아있으나 이벤트가 끊긴(버퍼 유실 등) 상황일 수 있다.
        etw_idle_s: u64,
        /// 지금까지 세션 자동 재시작 횟수
        etw_restarts: u32,
    },
}

/// ETW 세션 상태 공유 블록. 콜백(수집 스레드)과 heartbeat(송신)·supervisor 가 공유한다.
#[derive(Debug)]
pub struct EtwHealth {
    pub alive: AtomicBool,
    pub last_event_ms: AtomicU64,
    pub restarts: AtomicU32,
}

impl Default for EtwHealth {
    fn default() -> Self {
        EtwHealth {
            alive: AtomicBool::new(false),
            last_event_ms: AtomicU64::new(0),
            restarts: AtomicU32::new(0),
        }
    }
}

impl EtwHealth {
    /// 콜백에서 이벤트를 받을 때마다 호출(아주 저렴한 relaxed store).
    #[inline]
    pub fn mark_event(&self) {
        self.last_event_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// 마지막 이벤트 이후 경과 초. 아직 한 건도 없으면 0.
    pub fn idle_secs(&self) -> u64 {
        let last = self.last_event_ms.load(Ordering::Relaxed);
        if last == 0 {
            return 0;
        }
        now_ms().saturating_sub(last) / 1000
    }
}

/// 에이전트 내부 카운터 (heartbeat 로 보고)
#[derive(Default, Debug)]
pub struct Counters {
    pub emitted: AtomicU64,
    pub dropped_queue: AtomicU64,
    pub dropped_send: AtomicU64,
    pub parse_errors: AtomicU64,
}

pub enum Msg {
    Event(Envelope),
    Shutdown,
}

#[derive(Clone)]
pub struct Emitter {
    tx: SyncSender<Msg>,
    sid: Arc<str>,
    seq: Arc<AtomicU64>,
    pub counters: Arc<Counters>,
}

impl Emitter {
    pub fn new(queue_cap: usize, sid: &str) -> (Self, Receiver<Msg>) {
        let (tx, rx) = sync_channel(queue_cap);
        (
            Emitter {
                tx,
                sid: Arc::from(sid),
                seq: Arc::new(AtomicU64::new(0)),
                counters: Arc::new(Counters::default()),
            },
            rx,
        )
    }

    /// 논블로킹 투입. ETW 콜백에서 호출된다.
    pub fn emit(&self, body: EventBody) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let env = Envelope {
            v: SCHEMA_VERSION,
            sid: self.sid.clone(),
            seq,
            ts_ms: now_ms(),
            body,
        };
        match self.tx.try_send(Msg::Event(env)) {
            Ok(()) => {
                self.counters.emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn parse_error(&self) {
        self.counters.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// 송신 스레드에 종료를 알린다 (블로킹 send: 반드시 전달되어야 함).
    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 문자 경계를 지키며 자르고, NUL 및 기타 C0 제어문자(탭 제외)를 제거한다.
/// (JSON 이스케이프는 serde 가 하지만, 하위 시스템의 로그 인젝션 여지를 줄인다.)
pub fn clean(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars * 4));
    let mut n = 0usize;
    let mut truncated = false;
    for c in s.chars() {
        if n >= max_chars {
            truncated = true;
            break;
        }
        if c.is_control() && c != '\t' {
            out.push(' ');
        } else {
            out.push(c);
        }
        n += 1;
    }
    if truncated {
        out.push_str("…[truncated]");
    }
    out
}

/// 커널 Process 이벤트의 UserSID 필드(TOKEN_USER 구조체 + SID)를 "S-1-..." 문자열로 변환.
/// `ptr_size` 는 이벤트 헤더 기준 포인터 크기(x64 = 8). 잘못된 입력에는 None.
pub fn sid_from_token_user(buf: &[u8], ptr_size: usize) -> Option<String> {
    // TOKEN_USER = { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } } → 커널 이벤트에서는 2*ptr 크기
    let off = ptr_size.checked_mul(2)?;
    let sid = buf.get(off..)?;
    let revision = *sid.first()?;
    let count = *sid.get(1)? as usize;
    if revision != 1 || count > 15 {
        return None;
    }
    let auth_bytes = sid.get(2..8)?;
    let mut authority: u64 = 0;
    for b in auth_bytes {
        authority = (authority << 8) | *b as u64;
    }
    let mut s = format!("S-1-{authority}");
    for i in 0..count {
        let start = 8 + i * 4;
        let sub = sid.get(start..start + 4)?;
        let v = u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]]);
        s.push('-');
        s.push_str(&v.to_string());
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_truncates_on_char_boundary() {
        let s = "가나다라마";
        assert_eq!(clean(s, 3), "가나다…[truncated]");
        assert_eq!(clean(s, 10), s);
    }

    #[test]
    fn clean_strips_control_chars() {
        assert_eq!(clean("a\nb\r\0c\td", 100), "a b  c\td");
    }

    #[test]
    fn sid_parsing() {
        // 16바이트 TOKEN_USER 헤더 + S-1-5-21-1-2-3-1001
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 5]);
        for v in [21u32, 1, 2, 3, 1001] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(
            sid_from_token_user(&buf, 8).as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        // 잘린 버퍼는 None
        assert_eq!(sid_from_token_user(&buf[..20], 8), None);
        assert_eq!(sid_from_token_user(&[], 8), None);
    }

    #[test]
    fn queue_full_counts_drops_and_seq_keeps_increasing() {
        let (em, rx) = Emitter::new(2, "t");
        for _ in 0..5 {
            em.emit(EventBody::AgentStop { reason: "x".into() });
        }
        assert_eq!(em.counters.emitted.load(Ordering::Relaxed), 2);
        assert_eq!(em.counters.dropped_queue.load(Ordering::Relaxed), 3);
        let seqs: Vec<u64> = rx
            .try_iter()
            .filter_map(|m| match m {
                Msg::Event(e) => Some(e.seq),
                _ => None,
            })
            .collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn etw_stopped_and_heartbeat_shape() {
        let (em, rx) = Emitter::new(8, "run-1");
        em.emit(EventBody::EtwStopped { count: 2, detail: "x".into() });
        em.emit(EventBody::Heartbeat {
            uptime_s: 5,
            emitted: 1,
            dropped_queue: 0,
            dropped_send: 0,
            parse_errors: 0,
            etw_alive: false,
            etw_idle_s: 42,
            etw_restarts: 2,
        });
        let mut kinds = vec![];
        while let Ok(Msg::Event(e)) = rx.try_recv() {
            let v = serde_json::to_value(&e).unwrap();
            kinds.push(v["kind"].as_str().unwrap().to_string());
            if v["kind"] == "heartbeat" {
                assert_eq!(v["etw_alive"], false);
                assert_eq!(v["etw_idle_s"], 42);
                assert_eq!(v["etw_restarts"], 2);
            }
            if v["kind"] == "etw_stopped" {
                assert_eq!(v["count"], 2);
            }
        }
        assert_eq!(kinds, vec!["etw_stopped", "heartbeat"]);
    }

    #[test]
    fn health_idle_tracking() {
        let h = EtwHealth::default();
        assert_eq!(h.idle_secs(), 0); // 아직 이벤트 없음
        h.mark_event();
        assert!(h.idle_secs() < 2);
    }

    #[test]
    fn json_shape() {
        let (em, rx) = Emitter::new(4, "run-1");
        em.emit(EventBody::ProcStart {
            pid: 10,
            ppid: 4,
            session: 1,
            image: "a.exe".into(),
            cmdline: "a.exe -x".into(),
            user_sid: None,
        });
        let Msg::Event(e) = rx.recv().unwrap() else { panic!() };
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "proc_start");
        assert_eq!(v["sid"], "run-1");
        assert_eq!(v["seq"], 1);
        assert!(v.get("user_sid").is_none());
    }
}
