//! edr-lite: 악성코드 분석 VM 용 경량 텔레메트리 에이전트
//!
//! 사용법
//!   edr-lite.exe --config C:\edr\agent.toml            실 운영 (관리자 권한)
//!   edr-lite.exe --config C:\edr\agent.toml --test     릴레이 연결 테스트만 (ETW 미사용)
//!   edr-lite.exe --dry-run                             네트워크 없이 이벤트를 stdout 출력
//!
//! 설계 원칙
//!   - 단방향 (수집 → 릴레이). 원격 명령 수신 기능 없음
//!   - 클라우드 자격증명 없음. 릴레이만 GCP 에 쓸 수 있다
//!   - 게스트는 오염된 환경이라 가정: 에이전트 데이터는 "증거 후보"이지 진실이 아니다

#![cfg_attr(not(windows), allow(dead_code))]

mod config;
mod event;
mod sender;
mod tls;
#[cfg(windows)]
mod etw;

use event::{Emitter, EtwHealth, EventBody};
use sender::{HttpsTransport, SenderOpts, StdoutTransport, Transport};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    config: Option<PathBuf>,
    dry_run: bool,
    test: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { config: None, dry_run: false, test: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                a.config = Some(it.next().ok_or("--config 뒤에 경로가 필요합니다")?.into())
            }
            "--dry-run" => a.dry_run = true,
            "--test" => a.test = true,
            "--version" => {
                println!("edr-lite {VERSION}");
                std::process::exit(0);
            }
            other => return Err(format!("알 수 없는 인자: {other}")),
        }
    }
    if !a.dry_run && a.config.is_none() {
        return Err("--config <path> 또는 --dry-run 이 필요합니다".into());
    }
    Ok(a)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[edr] {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(args) {
        eprintln!("[edr] 치명적 오류: {e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    // ---- 설정 & 송신 경로 ----
    let (cfg, transport): (Option<config::Config>, Box<dyn Transport>) = if args.dry_run {
        (None, Box::new(StdoutTransport))
    } else {
        let path = args.config.as_ref().expect("checked");
        let cfg = config::Config::load(path)?;
        let pin = config::pin_bytes(&cfg.server_cert_sha256)?;
        let tls = tls::client_config(&cfg.ca_cert, &cfg.client_cert, &cfg.client_key, pin)?;
        // 키는 TLS 설정에 이미 로드됨 → 요청 시 디스크에서 제거 (인포스틸러가 훔쳐갈 키 제거)
        if cfg.wipe_client_key {
            match wipe_file(&cfg.client_key) {
                Ok(()) => eprintln!("[edr] client_key 디스크에서 삭제됨"),
                Err(e) => eprintln!("[edr] 경고: client_key 삭제 실패: {e}"),
            }
        }
        let t = HttpsTransport::new(cfg.relay_url.clone(), tls);
        (Some(cfg), Box::new(t))
    };

    let session_id = cfg.as_ref().map(|c| c.session_id.as_str()).unwrap_or("dry-run");
    let queue_cap = cfg.as_ref().map(|c| c.queue_capacity).unwrap_or(10_000);
    let opts = SenderOpts {
        batch_max_events: cfg.as_ref().map(|c| c.batch_max_events).unwrap_or(1),
        batch_max_bytes: cfg.as_ref().map(|c| c.batch_max_bytes).unwrap_or(64 * 1024),
        flush_interval: Duration::from_millis(cfg.as_ref().map(|c| c.flush_interval_ms).unwrap_or(500)),
    };
    let hb_secs = cfg.as_ref().map(|c| c.heartbeat_secs).unwrap_or(10);

    let (emitter, rx) = Emitter::new(queue_cap, session_id);
    let sender = sender::spawn_sender(rx, transport, opts, emitter.counters.clone());

    let own_pid = std::process::id();
    emitter.emit(EventBody::AgentStart { version: VERSION, agent_pid: own_pid });

    // ---- 연결 테스트 모드 ----
    if args.test {
        emitter.emit(EventBody::AgentStop { reason: "connection-test".into() });
        emitter.shutdown();
        let _ = sender.join();
        let c = &emitter.counters;
        if c.dropped_send.load(Ordering::Relaxed) > 0 {
            return Err("릴레이 전송 실패 (위 오류 메시지 확인)".into());
        }
        eprintln!("[edr] 연결 테스트 성공: 이벤트 2건 전송");
        return Ok(());
    }

    // ---- heartbeat ----
    let stop = Arc::new(AtomicBool::new(false));
    let health = Arc::new(EtwHealth::default());
    let hb = sender::spawn_heartbeat(
        emitter.clone(),
        Duration::from_secs(hb_secs),
        stop.clone(),
        health.clone(),
    );

    // ---- 종료 신호 ----
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = stop_tx.send(());
    })
    .map_err(|e| format!("Ctrl+C 핸들러 등록 실패: {e}"))?;

    // ---- ETW 수집 시작 (감독 스레드가 세션 중지 시 자동 재시작) ----
    #[cfg(windows)]
    let supervisor = {
        let opt = etw::Options {
            trace_name: cfg
                .as_ref()
                .and_then(|c| c.trace_name.clone())
                .unwrap_or_else(|| generated_trace_name(own_pid)),
            own_pid,
            image_loads: cfg.as_ref().map(|c| c.collect_image_loads).unwrap_or(true),
            network: cfg.as_ref().map(|c| c.collect_network).unwrap_or(true),
        };
        eprintln!("[edr] ETW 세션: {}", opt.trace_name);
        etw::spawn_supervisor(emitter.clone(), health.clone(), opt, stop.clone())
    };
    #[cfg(not(windows))]
    eprintln!("[edr] 경고: ETW 수집은 Windows 전용입니다. heartbeat 만 전송합니다.");

    eprintln!("[edr] 수집 시작 (session={session_id}, pid={own_pid}). Ctrl+C 로 종료");
    let _ = stop_rx.recv();
    eprintln!("[edr] 종료 중...");

    // 감독 스레드가 현재 ETW 세션을 정상 종료하도록 stop 설정 후 대기
    stop.store(true, Ordering::Relaxed);
    #[cfg(windows)]
    let _ = supervisor.join();
    let _ = hb.join();
    emitter.emit(EventBody::AgentStop { reason: "signal".into() });
    emitter.shutdown();
    // 릴레이 장애 시 무한 대기하지 않도록 상한을 둔다
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.join();
        let _ = done_tx.send(());
    });
    let _ = done_rx.recv_timeout(Duration::from_secs(10));
    Ok(())
}

/// 키 파일을 0 으로 덮어쓴 뒤 삭제. SSD·저널링 FS 에서는 원복 가능성이 남으므로
/// "완전 삭제"가 아니라 "일상적 탈취 난이도를 높이는" 수준임에 유의.
fn wipe_file(path: &Path) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 4096];
            let mut left = meta.len();
            f.seek(SeekFrom::Start(0))?;
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                f.write_all(&zeros[..n])?;
                left -= n as u64;
            }
            f.flush()?;
            let _ = f.sync_all();
        }
    }
    std::fs::remove_file(path)
}

/// 설정에 세션 이름이 없을 때 쓰는 평범한 이름. 고정 상수 노출을 피하되
/// 분석 분류를 위해 접두사는 유지. (은닉이 목적이면 설정에서 직접 지정)
fn generated_trace_name(pid: u32) -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("WinTelemetry-{:x}-{pid}", t & 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_file_zeroes_and_removes() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("edr-wipe-test-{}.key", std::process::id()));
        std::fs::write(&p, b"SECRETKEYMATERIAL").unwrap();
        wipe_file(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn generated_name_is_plain_ascii() {
        let n = generated_trace_name(1234);
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert!(n.contains("1234"));
    }
}
