//! 배치 송신 스레드 + heartbeat 스레드.
//! 실제 전송 방식은 `Transport` 구현체가 정한다 (Cloud Logging 직접 전송은 gcp.rs).

use crate::event::{Counters, Emitter, EtwHealth, EventBody, Msg};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub trait Transport: Send {
    /// NDJSON 배치 전송. 실패 시 Err.
    fn send(&mut self, body: &[u8]) -> Result<(), String>;
}

/// --dry-run 용: stdout 에 NDJSON 출력
pub struct StdoutTransport;

impl Transport for StdoutTransport {
    fn send(&mut self, body: &[u8]) -> Result<(), String> {
        let mut out = std::io::stdout().lock();
        out.write_all(body).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())
    }
}

pub struct SenderOpts {
    pub batch_max_events: usize,
    pub batch_max_bytes: usize,
    pub flush_interval: Duration,
}

const RETRY_BACKOFF_MS: [u64; 3] = [250, 1000, 3000];

pub fn spawn_sender(
    rx: Receiver<Msg>,
    mut transport: Box<dyn Transport>,
    opts: SenderOpts,
    counters: Arc<Counters>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("edr-sender".into())
        .spawn(move || {
            let mut buf: Vec<u8> = Vec::with_capacity(opts.batch_max_bytes);
            let mut n: usize = 0;
            let mut deadline = Instant::now() + opts.flush_interval;

            let mut flush = |buf: &mut Vec<u8>, n: &mut usize| {
                if *n == 0 {
                    return;
                }
                let mut ok = false;
                for (i, backoff) in RETRY_BACKOFF_MS.iter().enumerate() {
                    match transport.send(buf) {
                        Ok(()) => {
                            ok = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!("[edr] 송신 실패 ({}/{}): {e}", i + 1, RETRY_BACKOFF_MS.len());
                            std::thread::sleep(Duration::from_millis(*backoff));
                        }
                    }
                }
                if !ok {
                    counters
                        .dropped_send
                        .fetch_add(*n as u64, Ordering::Relaxed);
                }
                buf.clear();
                *n = 0;
            };

            loop {
                let timeout = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(timeout) {
                    Ok(Msg::Event(env)) => {
                        match serde_json::to_vec(&env) {
                            Ok(line) => {
                                // 이 이벤트를 넣으면 바이트 상한을 넘는 경우 먼저 비운다
                                if n > 0 && buf.len() + line.len() + 1 > opts.batch_max_bytes {
                                    flush(&mut buf, &mut n);
                                    deadline = Instant::now() + opts.flush_interval;
                                }
                                buf.extend_from_slice(&line);
                                buf.push(b'\n');
                                n += 1;
                            }
                            Err(_) => {
                                counters.parse_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if n >= opts.batch_max_events || buf.len() >= opts.batch_max_bytes {
                            flush(&mut buf, &mut n);
                            deadline = Instant::now() + opts.flush_interval;
                        }
                    }
                    Ok(Msg::Shutdown) => {
                        // 큐에 남은 이벤트까지 비우고 종료
                        while let Ok(Msg::Event(env)) = rx.try_recv() {
                            if let Ok(line) = serde_json::to_vec(&env) {
                                buf.extend_from_slice(&line);
                                buf.push(b'\n');
                                n += 1;
                            }
                        }
                        flush(&mut buf, &mut n);
                        return;
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        flush(&mut buf, &mut n);
                        deadline = Instant::now() + opts.flush_interval;
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        flush(&mut buf, &mut n);
                        return;
                    }
                }
            }
        })
        .expect("sender thread spawn")
}

/// 주기적 heartbeat. 수집 측(Google Function)은 heartbeat 공백으로 에이전트 중단(악성코드에 의한 kill 등)을 탐지한다.
pub fn spawn_heartbeat(
    emitter: Emitter,
    interval: Duration,
    stop: Arc<AtomicBool>,
    health: Arc<EtwHealth>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("edr-heartbeat".into())
        .spawn(move || {
            let start = Instant::now();
            let tick = Duration::from_millis(200);
            let mut next = Instant::now() + interval;
            while !stop.load(Ordering::Relaxed) {
                if Instant::now() >= next {
                    let c = &emitter.counters;
                    emitter.emit(EventBody::Heartbeat {
                        uptime_s: start.elapsed().as_secs(),
                        emitted: c.emitted.load(Ordering::Relaxed),
                        dropped_queue: c.dropped_queue.load(Ordering::Relaxed),
                        dropped_send: c.dropped_send.load(Ordering::Relaxed),
                        parse_errors: c.parse_errors.load(Ordering::Relaxed),
                        etw_alive: health.alive.load(Ordering::Relaxed),
                        etw_idle_s: health.idle_secs(),
                        etw_restarts: health.restarts.load(Ordering::Relaxed),
                    });
                    next += interval;
                }
                std::thread::sleep(tick);
            }
        })
        .expect("heartbeat thread spawn")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Capture(Arc<Mutex<Vec<Vec<u8>>>>, usize);
    impl Transport for Capture {
        fn send(&mut self, body: &[u8]) -> Result<(), String> {
            if self.1 > 0 {
                self.1 -= 1;
                return Err("fail".into());
            }
            self.0.lock().unwrap().push(body.to_vec());
            Ok(())
        }
    }

    fn opts(max: usize) -> SenderOpts {
        SenderOpts {
            batch_max_events: max,
            batch_max_bytes: 1 << 20,
            flush_interval: Duration::from_millis(100),
        }
    }

    #[test]
    fn batches_by_count_and_flushes_on_shutdown() {
        let (em, rx) = Emitter::new(100, "t");
        let got = Arc::new(Mutex::new(Vec::new()));
        let h = spawn_sender(rx, Box::new(Capture(got.clone(), 0)), opts(3), em.counters.clone());
        for i in 0..7 {
            em.emit(EventBody::ImageLoad { pid: i, path: "x".into() });
        }
        em.shutdown();
        h.join().unwrap();
        let batches = got.lock().unwrap();
        let lines: Vec<usize> = batches
            .iter()
            .map(|b| b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count())
            .collect();
        assert_eq!(lines.iter().sum::<usize>(), 7);
        assert_eq!(&lines[..2], &[3, 3]);
    }

    #[test]
    fn retries_then_succeeds() {
        let (em, rx) = Emitter::new(100, "t");
        let got = Arc::new(Mutex::new(Vec::new()));
        let h = spawn_sender(rx, Box::new(Capture(got.clone(), 2)), opts(1), em.counters.clone());
        em.emit(EventBody::ImageLoad { pid: 1, path: "x".into() });
        em.shutdown();
        h.join().unwrap();
        assert_eq!(got.lock().unwrap().len(), 1);
        assert_eq!(em.counters.dropped_send.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn counts_dropped_after_retries_exhausted() {
        let (em, rx) = Emitter::new(100, "t");
        let got = Arc::new(Mutex::new(Vec::new()));
        let h = spawn_sender(rx, Box::new(Capture(got.clone(), 99)), opts(1), em.counters.clone());
        em.emit(EventBody::ImageLoad { pid: 1, path: "x".into() });
        em.shutdown();
        h.join().unwrap();
        assert_eq!(em.counters.dropped_send.load(Ordering::Relaxed), 1);
    }
}
