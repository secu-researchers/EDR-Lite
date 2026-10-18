# edr-lite

악성코드 분석용 Windows VM 안에서 동작하는 경량 텔레메트리 에이전트다.
커널 ETW로 프로세스, 이미지 로드, 네트워크 이벤트를 수집해 릴레이 VM으로 mTLS 단방향 전송한다.
탐지나 차단은 하지 않고, 분석 중 일어난 일을 VM 밖에 기록하는 센서 역할만 한다.

```
[분석 VM: edr-lite.exe] --mTLS(TLS 1.3, 인증서 핀)--> [릴레이 VM] --> [로그 저장소]
```

## 주요 특징

- 커널 ETW 기반 수집: 프로세스 시작/종료, DLL·드라이버 이미지 로드, TCP/UDP 연결
- 단방향 전송: 릴레이에서 에이전트로 명령을 받는 기능이 없음
- 게스트에 클라우드 자격증명이 없음. 릴레이만 저장소에 기록
- 수집 중단 탐지: 주기적 heartbeat, 이벤트 일련번호(seq), ETW 세션 중지 감시와 자동 재시작
- 단일 exe 배포: VC++ 런타임 설치 불필요

## 수집 이벤트

| kind | 내용 |
|---|---|
| `proc_start` / `proc_stop` | 프로세스 시작 / 종료 |
| `proc_existing` | 에이전트 시작 시점에 이미 실행 중이던 프로세스 |
| `image_load` | 프로세스가 로드한 모듈 경로 |
| `net` | TCP connect/accept, UDP send |
| `heartbeat` | 에이전트 상태와 ETW 세션 상태 |
| `etw_stopped` / `etw_restarted` | ETW 세션 중지 감지 / 자동 재시작 |
| `agent_start` / `agent_stop` | 에이전트 시작 / 종료 |

모든 이벤트는 한 줄에 1건인 NDJSON이며, 공통 필드는 `v`, `sid`, `seq`, `ts_ms`다.
필드 상세는 `개발명세서.md`를 본다.

## 요구사항

- 빌드 머신: Windows, Rust(MSVC 툴체인), Visual Studio Build Tools
- 분석 VM: Windows 11 x64, 관리자(SYSTEM) 권한으로 실행
- 릴레이 VM: 클라이언트 인증서를 요구하는 HTTPS 수집 서버(별도 구현), OpenSSL(인증서 발급용)

## 빌드

```powershell
cargo build --release
```

결과물은 `target\release\edr-lite.exe`다.

## 설정

`agent.example.toml`을 복사해 `agent.toml`로 만들고 값을 채운다.

| 키 | 필수 | 설명 |
|---|---|---|
| `relay_url` | 예 | 릴레이 수집 엔드포인트. `https://`만 허용 |
| `session_id` | 예 | 분석 회차 ID. 에이전트 인증서 CN과 같아야 함 |
| `ca_cert` | 예 | 릴레이 서버 인증서를 서명한 사설 CA(PEM) |
| `client_cert`, `client_key` | 예 | 회차용 클라이언트 인증서와 키(PEM) |
| `server_cert_sha256` | 예 | 릴레이 서버 인증서의 SHA-256 핀 |
| `wipe_client_key` | 아니오 | true면 키를 읽은 직후 디스크에서 삭제 |
| `trace_name` | 아니오 | ETW 세션 이름. 생략 시 자동 생성 |
| `heartbeat_secs`, `batch_max_events`, `flush_interval_ms`, `queue_capacity` 등 | 아니오 | 주기와 배치, 큐 크기. 기본값은 `agent.example.toml` 참고 |

## 사용법

```powershell
# 이벤트 파싱 확인 (네트워크 없이 stdout 출력)
edr-lite.exe --dry-run

# 릴레이 연결 테스트 (이벤트 2건 전송 후 종료)
edr-lite.exe --config C:\edr\agent.toml --test

# 실제 수집 (관리자 권한, Ctrl+C로 종료)
edr-lite.exe --config C:\edr\agent.toml
```

### 릴레이 VM에서 직접 해야 하는 작업

1. Python 3.11 이상과 google-cloud-logging을 설치합니다 (edr-relay/requirements.txt).
2. relay.py, relay.toml, allowed_cn.txt를 배치하고, gen-certs.sh로 만든 인증서를 지정합니다.
3. GCP 서비스 계정 키를 놓고 GOOGLE_APPLICATION_CREDENTIALS로 지정합니다. 이 키는 릴레이에만 두고, 파일 접근 권한은 서비스 실행 계정만 읽게 제한합니다.
4. relay.py를 비특권 계정의 서비스(예: systemd)로 등록해 재부팅 후에도 자동 실행되게 합니다.
5. 방화벽을 설정합니다. 분석망 쪽 NIC에서는 수집 포트만 열고, 외부 방향은 GCP API(443)만 허용합니다.


## 배포 절차

1. 릴레이 VM에서 인증서를 만든다.
   - `scripts/gen-certs.sh ca` (최초 1회)
   - `scripts/gen-certs.sh server <릴레이 IP>` (출력되는 핀을 `server_cert_sha256`에 기록)
   - `scripts/gen-certs.sh agent <session-id>` (분석 회차마다, 기본 유효기간 1일)
2. 분석 VM의 `C:\edr\`에 `edr-lite.exe`, `agent.toml`, `ca.pem`, 에이전트 인증서와 키를 복사한다.
3. 관리자 PowerShell에서 하드닝 스크립트를 실행한다.
   `scripts\harden.ps1 -EdrDir C:\edr -SampleUser analyst -CreateSampleUser`
   - 에이전트를 SYSTEM 권한 부팅 자동 실행 작업으로 등록
   - `C:\edr`와 키 파일을 SYSTEM 전용 접근으로 잠금
   - 샘플 실행용 제한 계정 생성
4. `--test`로 연결을 확인하고 `--dry-run`으로 이벤트가 나오는지 확인한다.
5. 이 상태에서 VM 스냅샷을 찍고, 제한 계정으로 샘플을 실행한다.
6. 분석이 끝나면 스냅샷을 복원하고 릴레이에서 해당 회차 인증서를 폐기한다.

## 릴레이 측 요구사항

- 클라이언트 인증서 필수, 인증서 CN과 이벤트의 `sid` 일치 확인
- 요청 본문 크기 상한, 줄 단위 JSON 검증, 알 수 없는 `kind` 거부
- `seq` 공백과 heartbeat의 드롭 카운터를 비교해 이상 징후 경보
- heartbeat가 `3 x heartbeat_secs` 이상 끊기거나 `etw_alive=false`이면 경보
- 게스트가 보낸 데이터는 신뢰할 수 없는 입력으로 취급

## 한계

- 사용자 모드 프로세스이므로 SYSTEM 권한 악성코드는 에이전트를 종료하거나 방해할 수 있다. 이 경우는 heartbeat 공백과 `etw_stopped`로 탐지하며, 메모리 덤프와 PCAP 같은 VM 밖 증거로 교차 검증해야 한다.
- 커널 ETW 세션 이름은 `logman query -ets`로 보인다.
- x64 게스트만 지원한다.
- `ts_ms`는 게스트 시계 기준이므로 릴레이 수신 시각을 따로 기록해야 한다.

## 문서

- `개발명세서.md`: 소스 구조, 모듈, 스키마, 보안 설계
