//! Windows 커널 ETW 수집부 (NT Kernel Logger 계열, 관리자 권한 필요).
//!
//! 구독 대상
//!   - Process   : Start(1) / End(2) / DCStart(3, 시작 시점 기존 프로세스)
//!   - ImageLoad : Load(10)
//!   - TcpIp     : ConnectIPv4(12) / AcceptIPv4(15) / ConnectIPv6(28) / AcceptIPv6(31)
//!   - UdpIp     : SendIPv4(10) / SendIPv6(26)  (pid,dst,dport 기준 60초 중복 제거)
//!
//! 콜백은 ETW 처리 스레드에서 호출되므로 파싱 → Emitter::emit(논블로킹)만 수행한다.

use crate::event::{
    clean, sid_from_token_user, Emitter, EtwHealth, EventBody, MAX_CMDLINE, MAX_IMAGE, MAX_PATH,
};
use ferrisetw::parser::Parser;
use ferrisetw::provider::kernel_providers::{self, KernelProvider};
use ferrisetw::provider::Provider;
use ferrisetw::trace::stop_trace_by_name;
use ferrisetw::{EventRecord, KernelTrace, SchemaLocator, GUID};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// UdpIp 커널 이벤트 클래스 {BF3A50C5-A9C9-4988-A005-2DF0B7C80F80}, 플래그는 TcpIp 와 동일
static UDP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80),
    0x0001_0000, // EVENT_TRACE_FLAG_NETWORK_TCPIP
);

const EVENT_HEADER_FLAG_64_BIT_HEADER: u16 = 0x0020;

fn s(p: &Parser, name: &str) -> Option<String> {
    if let Ok(v) = p.try_parse::<String>(name) {
        return Some(v);
    }
    // ANSI 문자열이 UTF-8 이 아닐 경우(악성코드가 일부러 넣는 경우 포함) 손실 변환
    p.try_parse::<Vec<u8>>(name)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).trim_end_matches('\0').to_string())
}

fn u32f(p: &Parser, name: &str) -> Option<u32> {
    p.try_parse::<u32>(name).ok()
}

/// TDH PORT 출력형은 네트워크 바이트 순서
fn port(p: &Parser, name: &str) -> Option<u16> {
    p.try_parse::<u16>(name).ok().map(u16::from_be)
}

fn ip(p: &Parser, name: &str) -> Option<IpAddr> {
    p.try_parse::<IpAddr>(name).ok()
}

pub struct Options {
    pub trace_name: String,
    pub own_pid: u32,
    pub image_loads: bool,
    pub network: bool,
}

/// 커널 세션을 만들고 처리 스레드를 띄운다.
/// 반환: (세션 핸들, 처리 스레드). 처리 스레드가 끝나면 = 세션이 중지된 것.
fn build_and_start(
    em: &Emitter,
    health: &Arc<EtwHealth>,
    opt: &Options,
) -> Result<(KernelTrace, JoinHandle<()>), String> {
    // 이전 비정상 종료로 남은 동일 이름 세션 정리 (없으면 오류 무시)
    let _ = stop_trace_by_name(&opt.trace_name);

    // ---------------- Process ----------------
    let em_p = em.clone();
    let h_p = health.clone();
    let process = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            h_p.mark_event();
            let op = rec.opcode();
            if !matches!(op, 1..=3) {
                return;
            }
            let Ok(schema) = loc.event_schema(rec) else {
                em_p.parse_error();
                return;
            };
            let p = Parser::create(rec, &schema);
            let (Some(pid), Some(ppid)) = (u32f(&p, "ProcessId"), u32f(&p, "ParentId")) else {
                em_p.parse_error();
                return;
            };
            let image = clean(&s(&p, "ImageFileName").unwrap_or_default(), MAX_IMAGE);
            let body = match op {
                1 => {
                    let ptr = if rec.event_flags() & EVENT_HEADER_FLAG_64_BIT_HEADER != 0 { 8 } else { 4 };
                    EventBody::ProcStart {
                        pid,
                        ppid,
                        session: u32f(&p, "SessionId").unwrap_or(u32::MAX),
                        image,
                        cmdline: clean(&s(&p, "CommandLine").unwrap_or_default(), MAX_CMDLINE),
                        user_sid: p
                            .try_parse::<Vec<u8>>("UserSID")
                            .ok()
                            .and_then(|b| sid_from_token_user(&b, ptr)),
                    }
                }
                2 => EventBody::ProcStop {
                    pid,
                    ppid,
                    exit_code: u32f(&p, "ExitStatus").unwrap_or(0),
                    image,
                },
                _ => EventBody::ProcExisting {
                    pid,
                    ppid,
                    image,
                    cmdline: clean(&s(&p, "CommandLine").unwrap_or_default(), MAX_CMDLINE),
                },
            };
            em_p.emit(body);
        })
        .build();

    let mut builder = KernelTrace::new()
        .named(opt.trace_name.clone())
        .enable(process);

    // ---------------- ImageLoad ----------------
    if opt.image_loads {
        let em_i = em.clone();
        let h_i = health.clone();
        let own = opt.own_pid;
        let image = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
            .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                h_i.mark_event();
                if rec.opcode() != 10 {
                    return; // DCStart(기존 로드 모듈 수천 건)는 생략
                }
                let Ok(schema) = loc.event_schema(rec) else {
                    em_i.parse_error();
                    return;
                };
                let p = Parser::create(rec, &schema);
                let Some(pid) = u32f(&p, "ProcessId") else {
                    em_i.parse_error();
                    return;
                };
                if pid == own {
                    return;
                }
                em_i.emit(EventBody::ImageLoad {
                    pid,
                    path: clean(&s(&p, "FileName").unwrap_or_default(), MAX_PATH),
                });
            })
            .build();
        builder = builder.enable(image);
    }

    // ---------------- Network ----------------
    if opt.network {
        let own = opt.own_pid;

        let em_t = em.clone();
        let h_t = health.clone();
        let tcp = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
            .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                h_t.mark_event();
                let op = match rec.opcode() {
                    12 | 28 => "connect",
                    15 | 31 => "accept",
                    _ => return,
                };
                match net_body(rec, loc, "tcp", op, own) {
                    Ok(Some(body)) => em_t.emit(body),
                    Ok(None) => {}
                    Err(()) => em_t.parse_error(),
                }
            })
            .build();

        let em_u = em.clone();
        let h_u = health.clone();
        let mut seen: HashMap<(u32, IpAddr, u16), Instant> = HashMap::new();
        let udp = Provider::kernel(&UDP_IP_PROVIDER)
            .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                h_u.mark_event();
                if !matches!(rec.opcode(), 10 | 26) {
                    return;
                }
                let body = match net_body(rec, loc, "udp", "send", own) {
                    Ok(Some(b)) => b,
                    Ok(None) => return,
                    Err(()) => {
                        em_u.parse_error();
                        return;
                    }
                };
                if let EventBody::Net { pid, ref dst, dport, .. } = body {
                    let Ok(dst_ip) = dst.parse::<IpAddr>() else { return };
                    let now = Instant::now();
                    let key = (pid, dst_ip, dport);
                    if let Some(t) = seen.get(&key) {
                        if now.duration_since(*t) < Duration::from_secs(60) {
                            return;
                        }
                    }
                    if seen.len() > 8192 {
                        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
                        if seen.len() > 8192 {
                            seen.clear(); // 폭주 상황 방어
                        }
                    }
                    seen.insert(key, now);
                }
                em_u.emit(body);
            })
            .build();

        builder = builder.enable(tcp).enable(udp);
    }

    // start_and_process() 는 처리 결과를 버리므로 세션 중지를 알 수 없다.
    // start() 로 핸들을 받아 처리 스레드를 직접 띄우고, 스레드 종료 = 세션 중지로 감지한다.
    let (trace, handle) = builder
        .start()
        .map_err(|e| format!("ETW 커널 세션 시작 실패 (관리자 권한 필요): {e:?}"))?;

    let proc_thread = std::thread::Builder::new()
        .name("edr-etw-process".into())
        .spawn(move || {
            // 세션이 중지될 때까지 블로킹. 반환되면 수집이 끝난 것.
            let _ = KernelTrace::process_from_handle(handle);
        })
        .map_err(|e| format!("ETW 처리 스레드 생성 실패: {e}"))?;

    Ok((trace, proc_thread))
}

/// ETW 세션 감독 스레드.
/// 세션을 시작하고, 외부 요인(샘플의 `logman stop` 등)으로 중지되면 자동 재시작한다.
/// 중지/재시작은 모두 이벤트로 릴레이에 보고되므로, 수집 공백이 "조용히" 지나가지 않는다.
///
/// `stop` 이 set 되면 현재 세션을 정상 종료하고 스레드를 끝낸다.
pub fn spawn_supervisor(
    em: Emitter,
    health: Arc<EtwHealth>,
    opt: Options,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("edr-etw-supervisor".into())
        .spawn(move || {
            // 재시작 폭주 방지용 백오프
            const BACKOFF: [u64; 4] = [1, 2, 5, 10];
            let mut fail_streak = 0usize;

            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match build_and_start(&em, &health, &opt) {
                    Ok((trace, proc_thread)) => {
                        fail_streak = 0;
                        health.alive.store(true, Ordering::Relaxed);
                        let n = health.restarts.load(Ordering::Relaxed);
                        if n > 0 {
                            em.emit(EventBody::EtwRestarted { count: n });
                        }

                        // 처리 스레드가 끝나거나(세션 중지) stop 이 설정될 때까지 감시
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                let _ = trace.stop(); // 처리 스레드를 깨워 반환시킨다
                                let _ = proc_thread.join();
                                health.alive.store(false, Ordering::Relaxed);
                                return;
                            }
                            if proc_thread.is_finished() {
                                // 우리가 멈춘 게 아닌데 세션이 끝남 = 외부 중지
                                health.alive.store(false, Ordering::Relaxed);
                                let _ = proc_thread.join();
                                let _ = trace.stop();
                                let count =
                                    health.restarts.fetch_add(1, Ordering::Relaxed) + 1;
                                em.emit(EventBody::EtwStopped {
                                    count,
                                    detail: "kernel session stopped externally".into(),
                                });
                                break; // 바깥 loop 에서 재시작
                            }
                            std::thread::sleep(Duration::from_millis(250));
                        }
                    }
                    Err(e) => {
                        health.alive.store(false, Ordering::Relaxed);
                        let count = health.restarts.fetch_add(1, Ordering::Relaxed) + 1;
                        em.emit(EventBody::EtwStopped {
                            count,
                            detail: format!("restart failed: {e}"),
                        });
                        let wait = BACKOFF[fail_streak.min(BACKOFF.len() - 1)];
                        fail_streak += 1;
                        // 백오프 동안에도 stop 에 반응
                        for _ in 0..(wait * 4) {
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(250));
                        }
                    }
                }
            }
        })
        .expect("supervisor thread spawn")
}

/// Ok(None) = 의도적으로 건너뜀(에이전트 자신의 트래픽), Err = 파싱 실패
fn net_body(
    rec: &EventRecord,
    loc: &SchemaLocator,
    proto: &'static str,
    op: &'static str,
    own_pid: u32,
) -> Result<Option<EventBody>, ()> {
    let schema = loc.event_schema(rec).map_err(|_| ())?;
    let p = Parser::create(rec, &schema);
    let pid = u32f(&p, "PID").ok_or(())?;
    if pid == own_pid {
        // 에이전트 자신의 릴레이 연결은 기록하지 않는다 (피드백 루프 방지)
        return Ok(None);
    }
    Ok(Some(EventBody::Net {
        pid,
        proto,
        op,
        src: ip(&p, "saddr").ok_or(())?.to_string(),
        sport: port(&p, "sport").ok_or(())?,
        dst: ip(&p, "daddr").ok_or(())?.to_string(),
        dport: port(&p, "dport").ok_or(())?,
    }))
}
