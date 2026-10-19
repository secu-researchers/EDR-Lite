# edr-lite

악성코드 분석용 Windows VM 안에서 동작하는 경량 텔레메트리 에이전트다.
커널 ETW로 프로세스, 이미지 로드, 네트워크 이벤트를 수집해 Google Cloud Logging으로 직접 전송한다.
탐지나 차단은 하지 않고, 분석 중 일어난 일을 VM 밖에 기록하는 센서 역할만 한다.

```
[분석 VM: edr-lite.exe] --TLS 1.3--> [Cloud Logging: lab_malware]
                                          |  로그 싱크
                                          v
                                    [Pub/Sub] --> [Function: edr-ingest] --> [BigQuery: events]
                                                        |                         ^
                                                        +--> [Discord 경보]       |
[Cloud Scheduler] --> [Function: edr-watchdog] ---------+--(조회)-----------------+
```

## 주요 특징

- 커널 ETW 기반 수집: 프로세스 시작/종료, 이미지 로드, TCP/UDP 연결
- 직접 전송: 게스트가 Cloud Logging `entries.write`를 호출한다. 서비스 계정에는 `Logs Writer`만 부여해 쓰기 전용으로 둔다
- 단방향: 에이전트가 원격 명령을 받는 기능이 없다
- 수집 중단 탐지: heartbeat, 이벤트 일련번호(`seq`), ETW 세션 중지 감시와 자동 재시작. 판정과 경보는 Google Function이 맡는다
- TLS 1.3 전용, 에이전트에 내장한 공개 루트 CA만 신뢰한다 (OS 인증서 저장소 미사용)
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

공통 필드는 `v`, `sid`, `seq`, `ts_ms`다. 필드 상세는 `개발명세서.md`를 본다.

## 요구사항

- 빌드 머신: Windows, Rust(MSVC 툴체인), Visual Studio Build Tools
- 분석 VM: Windows 11 x64, 관리자(SYSTEM) 권한 실행, `logging.googleapis.com`과 `oauth2.googleapis.com`의 443 포트에 접근 가능
- GCP: 이 용도 전용 프로젝트(결제 연결), 설정 스크립트를 실행할 PC에 Cloud SDK(`gcloud`, `bq`)

## 빌드

```powershell
cargo build --release
```

결과물은 `target\release\edr-lite.exe`다.

## 설정

`agent.example.toml`을 복사해 `agent.toml`로 만들고 값을 채운다. 설정 파일은 빌드와 무관하며 실행할 때 `--config`로 지정한다.

| 키 | 필수 | 설명 |
|---|---|---|
| `gcp_project_id` | 예 | EDR 전용 GCP 프로젝트 ID |
| `sa_key_path` | 예 | `Logs Writer` 역할만 가진 서비스 계정 키(JSON) 경로 |
| `session_id` | 예 | 분석 회차 ID. 모든 이벤트의 `sid`가 된다 |
| `log_name` | 아니오 | Cloud Logging 로그 이름. 기본 `lab_malware` |
| `wipe_sa_key` | 아니오 | true면 키를 메모리에 올린 직후 키 파일을 덮어쓰고 삭제 |
| `trace_name` | 아니오 | ETW 세션 이름. 생략 시 자동 생성 |
| `heartbeat_secs`, `batch_max_events`, `flush_interval_ms`, `queue_capacity` 등 | 아니오 | 주기, 배치, 큐 크기. 기본값은 `agent.example.toml` 참고 |

`heartbeat_secs`를 바꾸면 Function의 `HEARTBEAT_SECS`도 같은 값 이상으로 맞춘다.

## 사용법

```powershell
# 이벤트 파싱 확인 (네트워크 없이 stdout 출력)
edr-lite.exe --dry-run

# Cloud Logging 전송 테스트 (이벤트 2건 전송 후 종료)
edr-lite.exe --config C:\edr\agent.toml --test

# 실제 수집 (관리자 권한, Ctrl+C로 종료)
edr-lite.exe --config C:\edr\agent.toml
```

## 배포 절차

1. **GCP 구성**: 전용 프로젝트를 만들고 `gcp\setup.ps1 -ProjectId <프로젝트 ID>`를 검토한 뒤 실행한다. 서비스 계정, Pub/Sub, BigQuery, 로그 싱크, Function 2개, Scheduler 작업을 만든다. 월 예산 알림(약 5,000원)은 콘솔에서 직접 만든다.
2. **서비스 계정 키 발급**: `gcp\revoke-key.ps1 -ProjectId <ID> -Action New -OutFile <저장소 밖 경로>`
3. **분석 VM 배치**: `C:\edr\`에 `edr-lite.exe`, `agent.toml`, `sa-key.json`을 복사한다.
4. **OS 하드닝** (관리자 PowerShell): `scripts\harden.ps1 -EdrDir C:\edr -SampleUser analyst -CreateSampleUser`
   - 에이전트를 SYSTEM 권한 부팅 자동 실행 작업으로 등록
   - `C:\edr`를 SYSTEM과 Administrators 전용으로, `*.key`와 `*.json`은 SYSTEM 전용으로 잠금
   - 샘플 실행용 제한 계정 생성
5. **전송 확인**: 키가 SYSTEM 전용이므로 `--test`는 SYSTEM 권한으로 실행한다(작업 스케줄러에서 SYSTEM 계정으로 한 번 실행하는 방식). `wipe_sa_key = true`이면 테스트도 키 파일을 지우므로 테스트 중에는 끄거나 키를 다시 복사할 준비를 한다.
6. **결과 확인**: BigQuery `edr_logs.events`에 이벤트가 들어오고 Discord 경보 채널이 동작하는지 본다.
7. **스냅샷**: 이 상태에서 VM 스냅샷을 찍는다. 키 파일은 스냅샷에 포함되므로 복원할 때마다 되살아난다.
8. 제한 계정으로 샘플을 실행하고, 분석이 끝나면 스냅샷을 복원한다.

## 감시와 경보

Function이 BigQuery 적재 시점과 주기 점검에서 판정한다. 같은 (세션, 사유) 경보는 30분에 한 번만 보낸다.

| 사유 | 조건 |
|---|---|
| `etw_stopped` | ETW 커널 세션이 외부 요인으로 중지됨 |
| `etw_not_alive` | heartbeat에 `etw_alive=false` |
| `heartbeat_silence` | 마지막 heartbeat(없으면 시작) 이후 `3 x heartbeat_secs` 초과 |
| `seq_gap` | heartbeat의 `seq`에서 수신한 고유 `seq`와 드롭 카운터를 뺀 값이 0보다 큼 |
| `invalid_event` | 형식·범위·크기 검증을 통과하지 못한 이벤트 (적재하지 않음) |

정상 종료(`agent_stop`)한 세션은 공백 경보에서 제외한다.

## 키 유출 시 대응

회차별 재발급과 단기 토큰은 쓰지 않는다. 장기 키 한 개를 유지하므로 유출이 의심되면 즉시 폐기한다.

1. `gcp\revoke-key.ps1 -ProjectId <ID> -Action List`로 키 ID를 확인한다.
2. `-Action Revoke -KeyId <ID> -DisableAccount`로 키를 삭제하고 서비스 계정을 비활성화한다.
3. 의심 시점 이후 `events`를 검토한다. 위조 로그는 분석 자료로 보고 증거로 쓰지 않는다.
4. 서비스 계정을 다시 활성화하고 `-Action New`로 새 키를 발급해 분석 VM에 복사한 뒤 에이전트를 재시작한다.

## 보안 설계와 수용한 위험

| 항목 | 내용 |
|---|---|
| 자격증명 | 쓰기 전용(`Logs Writer`) 서비스 계정, EDR 전용 프로젝트, 키는 메모리에만 보관, `wipe_sa_key`로 디스크 키 삭제, SYSTEM 전용 파일 권한 |
| 통신 | TLS 1.3, 내장 루트 CA만 신뢰, 프록시 환경변수 무시, 리다이렉트 금지, 토큰 엔드포인트는 `oauth2.googleapis.com`만 허용 |
| 로그 삭제 | 서비스 계정에 읽기·삭제 권한이 없다. `_Default` 싱크를 끄고 BigQuery 파티션을 30일 후 만료시킨다 |
| 비용 | 월 5,000원 내외를 목표로 하며 위험을 수용한다. 허용한 `kind` 외 이벤트는 적재하지 않는다. 예산 알림은 경고만 하고 지출을 막지 않는다 |
| 수용한 위험 | 장기 키가 게스트에 있고 스냅샷에도 남는다. 분석 VM의 인터넷 통신은 차단하지 않는다(VPN 경유는 방화벽 정책에서 처리). 키가 유출되면 위조 로그가 들어올 수 있고, 위조 heartbeat로 생존 판정을 속일 수 있으므로 호스트 측 증거(PCAP 등)와 교차 검증한다 |

## 알려진 한계

- 사용자 모드 프로세스이므로 SYSTEM 권한 악성코드는 에이전트를 종료하거나 방해할 수 있다. heartbeat 공백과 `etw_stopped`로 탐지한다.
- 커널 ETW 세션 이름은 `logman query -ets`로 보인다.
- x64 게스트만 지원한다.
- `ts_ms`는 게스트 시계 기준이다. Cloud Logging 수신 시각(`recv_time`)을 기준으로 삼는다.
- 에이전트는 메모리 큐만 쓴다. 네트워크가 끊기면 큐가 차는 만큼 `dropped_queue`와 `dropped_send`가 늘고 해당 이벤트는 유실된다.
- 실제 GCP에 대한 전송, 배포 스크립트, Function과 SQL은 아직 실행해 검증하지 않았다. 자동 테스트 범위는 `개발명세서.md`를 본다.

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `src\` | 에이전트 소스 (Rust) |
| `scripts\harden.ps1` | 분석 VM 하드닝 |
| `gcp\setup.ps1`, `gcp\revoke-key.ps1` | GCP 구성과 키 관리 스크립트 |
| `gcp\functions\edr_monitor\` | 감시 Function 소스와 단위 테스트 |
| `gcp\schema.sql` | BigQuery 스키마 |
| `agent.example.toml` | 설정 예시 |
| `개발명세서.md` | 소스 구조, 모듈, 스키마, 보안 설계 |
