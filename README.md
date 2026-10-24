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

> **검증 상태**: 에이전트의 단위 테스트(23개), Function의 단위 테스트(17개), 로컬 수집(`--dry-run`)은 실행해 확인했다.
> GCP 구성과 전송, 종단 간 시험, 정리 스크립트는 작성만 했고 끝까지 검증하지 못했다. 처음 쓰는 환경에서는 오류가 날 수 있으며,
> 반드시 이 용도 전용 GCP 프로젝트에서만 실행한다.

## 목차

1. [주요 특징](#주요-특징)
2. [수집 이벤트](#수집-이벤트)
3. [요구사항과 준비](#요구사항과-준비)
4. [빠른 시작: 원터치 테스트](#빠른-시작-원터치-테스트)
5. [수동 설치와 배포](#수동-설치와-배포)
6. [설정](#설정)
7. [사용법](#사용법)
8. [로그 확인](#로그-확인)
9. [감시와 경보](#감시와-경보)
10. [키 유출 시 대응](#키-유출-시-대응)
11. [보안 설계와 수용한 위험](#보안-설계와-수용한-위험)
12. [문제 해결](#문제-해결)
13. [알려진 한계](#알려진-한계)
14. [저장소 구성](#저장소-구성)
15. [라이선스](#라이선스)

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
| `net` | TCP connect/accept, UDP send (ICMP는 수집하지 않는다) |
| `heartbeat` | 에이전트 상태와 ETW 세션 상태 |
| `etw_stopped` / `etw_restarted` | ETW 세션 중지 감지 / 자동 재시작 |
| `agent_start` / `agent_stop` | 에이전트 시작 / 종료 |

모든 이벤트는 공통 필드 `v`, `sid`, `seq`, `ts_ms`, `kind`를 가지고, `kind`별 필드가 같은 단계에 이어진다.
필드 상세는 [개발명세서.md](개발명세서.md)를 본다.

## 요구사항과 준비

### 빌드와 테스트를 실행하는 PC

| 항목 | 설명 |
|---|---|
| OS | Windows 11 x64, 관리자 권한 PowerShell |
| Rust | MSVC 툴체인(`rustup`)과 Visual Studio Build Tools |
| Python | 3.12 이상 (Function 단위 테스트용, 추가 패키지 불필요) |
| Google Cloud SDK | `gcloud`와 `bq` 명령 |
| GCP | 이 용도 전용 프로젝트 하나, 결제 연결, 프로젝트 소유자 권한 계정 |
| Discord | (선택) 경보를 받을 테스트 서버의 웹훅. 없으면 경보를 BigQuery에만 기록한다 |

### 처음 한 번 하는 준비

1. 위 도구를 설치한 뒤 **새 PowerShell 창**을 연다(설치한 도구가 PATH에 잡히도록).
2. GCP에 로그인한다.

```powershell
gcloud auth login
gcloud config set project <PROJECT_ID>
```

3. 관리자 PowerShell 창에서 스크립트 실행 정책을 이 창에만 허용한다(창을 닫으면 원래대로 돌아간다).

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 분석 VM

Windows 11 x64, 관리자(SYSTEM) 권한 실행, `logging.googleapis.com`과 `oauth2.googleapis.com`의 443 포트에 접근 가능해야 한다.

## 빠른 시작: 원터치 테스트

`scripts\local-test\00_run.ps1` 하나로 빌드, 단위 테스트, 로컬 수집 확인, GCP 구성, 전송 확인, 종단 간 시험, 정리까지 순서대로 실행하고
항목별 결과(PASS / FAIL / SKIP / MANUAL)를 표로 보여 준다. 필요한 값은 실행 중에 물어본다.

### 1. 로컬 단계만 먼저 실행 (GCP에 접속하지 않음)

```powershell
cd <저장소 폴더>
.\scripts\local-test\00_run.ps1 -LocalOnly
```

### 2. 전체 실행 (GCP 단계 포함)

```powershell
.\scripts\local-test\00_run.ps1 -KeyPath C:\edr\sa-key.json
```

실행하면 아래를 차례로 묻는다.

| 질문 | 설명 |
|---|---|
| 실행 범위 | 전체(P~F) 또는 로컬만(P, A, B) |
| GCP 테스트 전용 프로젝트 ID | 6~30자, 소문자로 시작, 소문자/숫자/하이픈 |
| 리전, BigQuery 위치 | 기본값 `asia-northeast3`(서울). Enter로 받는다 |
| Discord 웹훅 주소 | 입력이 화면에 표시되지 않는다. 비우면 알림 없이 진행 |
| 서비스 계정 키 경로 | 저장소 밖 경로만 허용. 기본 `C:\edr\sa-key.json` |
| 설정 파일 경로 | 기본 `C:\edr\agent.toml` |
| 이미지 로드 측정 시간 | 분 단위(1~30) |
| 최종 확인 | 프로젝트 ID를 그대로 입력해야 진행 |

자주 쓰는 인자:

| 인자 | 설명 |
|---|---|
| `-LocalOnly` | 질문 없이 로컬 단계(P, A, B)만 실행 |
| `-Stages C,D,E,F` | 지정한 단계만 실행 |
| `-ProjectId`, `-Region`, `-BqLocation`, `-KeyPath`, `-ConfigPath`, `-ImageLoadMinutes` | 값을 미리 주면 다시 묻지 않는다 |
| `-SessionPrefix` | 세션 이름 접두사. 뒤에 월일시분이 붙는다 |
| `-ContinueOnFail` | 한 단계에 실패가 있어도 다음 단계를 계속 실행 |
| `-Yes` | 최종 확인 질문을 생략 (GCP를 바꾸므로 주의) |
| `-DeleteArtifacts` | 끝나면 수집 파일(`*.ndjson`)을 삭제 |

### 단계 설명

| 단계 | 하는 일 |
|---|---|
| P | 준비 확인: 관리자 권한, 도구 설치, gcloud 로그인, 프로젝트 접근 |
| A | 에이전트 단위 테스트(`cargo test`), Function 단위 테스트(`python -m unittest`), 릴리스 빌드 |
| B | `--dry-run`으로 실제 수집: 무해한 활동을 만들고 이벤트 종류, 필드, `seq`, heartbeat, ETW 중지 후 재시작을 확인 |
| C | `gcp\setup.ps1` 실행으로 GCP 리소스 생성, 생성 결과 확인, 서비스 계정 키 준비 |
| D | `agent.toml` 작성, `--test` 전송, BigQuery 도착 확인, 실패 시나리오(없는 프로젝트, 키 파일 오류, 전송 차단) |
| E | 실제 수집을 켠 종단 간 시험: 수집 경로, ETW 중지 경보, 경보 중복 방지, heartbeat 공백 경보, 정상 종료는 경보 없음, 전송 중단과 복구, 위조 로그 거부, 이미지 로드 양 측정 |
| F | 정리: 이번 실행이 만든 키 폐기와 파일 삭제, `_Default` 싱크 되돌리기, 방화벽 규칙과 설정 파일 정리 |

- 전체 실행은 20~40분 걸리고 소액의 GCP 비용이 발생할 수 있다.
- C 단계의 `setup.ps1`은 Function 배포 때문에 10~20분 걸린다. 진행 출력은 화면에 보이지 않고 끝난 뒤 로그 폴더에 저장된다.
- 한 단계에 FAIL이 있으면 이후 단계는 건너뛴다(`-ContinueOnFail`로 변경). GCP를 변경한 실행은 중간에 멈추거나 실패해도 마지막에 정리(F)를 시도한다.
- 월 예산 알림(C7)과 Discord 도착 확인은 사람이 직접 한다. 결과 표에 MANUAL로 표시된다.

### 결과와 로그

- 로그 폴더: `%TEMP%\edr-test-<시각>\` (`run.log`, `summary.txt`, `results.csv`, 명령별 출력)
- 이 폴더의 `*.ndjson` 파일에는 프로세스 명령줄이 들어 있어 경로, 사용자 이름, 인자에 든 값이 섞일 수 있다. 필요 없으면 `-DeleteArtifacts` 또는 직접 삭제한다.
- 종료 코드: FAIL이 하나라도 있으면 1, 없으면 0

### 안전 원칙

- 악성코드를 실행하지 않는다. 무해한 활동(`cmd echo`, `curl`, DNS 조회)만 만든다.
- 스크립트가 시작한 프로세스만 PID로 종료한다.
- 키, 웹훅 주소, 토큰은 화면과 로그에 남기지 않는다. 웹훅 주소는 `gcp\setup.ps1`을 실행하는 동안에만 환경변수로 전달하고 바로 지운다.
- 테스트 중 이 PC의 프로세스 이벤트가 GCP로 업로드된다. 민감한 작업은 닫고 진행한다.

## 수동 설치와 배포

원터치 테스트를 쓰지 않고 직접 배포할 때의 순서다.

1. **빌드**: `cargo build --release` (결과물 `target\release\edr-lite.exe`)
2. **GCP 구성**: 전용 프로젝트를 만들고 `gcp\setup.ps1 -ProjectId <PROJECT_ID>`를 검토한 뒤 실행한다. 서비스 계정, Pub/Sub, BigQuery, 로그 싱크, Function 2개, Scheduler 작업을 만든다. 웹훅 주소는 실행 중 숨김 입력창에 붙여 넣는다. 월 예산 알림(약 5,000원)은 콘솔에서 직접 만든다.
3. **서비스 계정 키 발급**: `gcp\revoke-key.ps1 -ProjectId <PROJECT_ID> -Action New -OutFile <저장소 밖 경로>`
4. **분석 VM 배치**: `C:\edr\`에 `edr-lite.exe`, `agent.toml`, `sa-key.json`을 복사한다.
5. **OS 하드닝** (관리자 PowerShell): `scripts\harden.ps1 -EdrDir C:\edr -SampleUser analyst -CreateSampleUser`
   - 에이전트를 SYSTEM 권한 부팅 자동 실행 작업으로 등록
   - `C:\edr`를 SYSTEM과 Administrators 전용으로, `*.key`와 `*.json`은 SYSTEM 전용으로 잠금
   - 샘플 실행용 제한 계정 생성
6. **전송 확인**: 키가 SYSTEM 전용이므로 `--test`는 SYSTEM 권한으로 실행한다(작업 스케줄러에서 SYSTEM 계정으로 한 번 실행하는 방식). `wipe_sa_key = true`이면 테스트도 키 파일을 지우므로 테스트 중에는 끄거나 키를 다시 복사할 준비를 한다.
7. **결과 확인**: BigQuery `edr_logs.events`에 이벤트가 들어오고 경보 채널이 동작하는지 본다.
8. **스냅샷**: 이 상태에서 VM 스냅샷을 찍는다. 키 파일은 스냅샷에 포함되므로 복원할 때마다 되살아난다.
9. 제한 계정으로 샘플을 실행하고, 분석이 끝나면 스냅샷을 복원한다.

### 폴더 배치

| 용도 | 위치 | 이유 |
|---|---|---|
| 소스, 스크립트 | 저장소 폴더 | 코드만 둔다 |
| 서비스 계정 키 | `C:\edr\sa-key.json` | 저장소 밖에 둔다. git에 올라가는 사고를 막는다 |
| 에이전트 설정 | `C:\edr\agent.toml` | 키 경로와 세션 ID가 들어 있다 |
| 테스트 결과 | `%TEMP%\edr-test-<시각>\` | 러너가 자동으로 만든다 |

`.gitignore`가 `agent.toml`, `sa-key*.json`, `*.key`를 제외한다. `revoke-key.ps1`은 저장소 안 경로에 키를 쓰지 않는다.

### 리전

- 리전은 GCP 리소스가 놓이는 지역이다. 기본값은 서울(`asia-northeast3`)이고, `setup.ps1`이 이 값으로 Function과 Scheduler를 만든다.
- BigQuery 데이터셋의 위치도 같은 값으로 만든다. 한 번 만들면 위치를 바꿀 수 없다.
- Cloud Logging과 Pub/Sub은 리전을 고르지 않는다.
- 콘솔에서 Function이나 Scheduler가 안 보이면 화면 위쪽 리전 필터를 서울 또는 "모든 리전"으로 바꾼다.

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
| `collect_image_loads` | 아니오 | 이미지 로드 수집 여부. 이벤트가 많아 비용이 늘어난다 |
| `heartbeat_secs`, `batch_max_events`, `flush_interval_ms`, `queue_capacity` 등 | 아니오 | 주기, 배치, 큐 크기. 기본값은 `agent.example.toml` 참고 |

- `heartbeat_secs`를 바꾸면 Function의 `HEARTBEAT_SECS`도 같은 값 이상으로 맞춘다(`setup.ps1 -HeartbeatSecs`).
- 알 수 없는 키가 있으면 에이전트가 시작하지 않는다.

### 세션 ID 규칙

- 길이 1~64자, 영문 대소문자, 숫자, `-`, `_`만 쓴다. 규칙에 맞지 않으면 에이전트가 시작하지 않고 Function도 그 이벤트를 거부한다.
- 같은 ID를 재사용하지 않는다. 순번(`seq`)이 1부터 다시 시작해 이전 기록과 섞이고, 1분 안에 재시작하면 일부 행이 중복으로 처리되어 버려질 수 있다.
- 의미 있는 이름이 좋다. 예: `sample-emotet-20261024-01`
- 게스트가 정하는 값이므로 인증 근거로 쓰지 않는다.

## 사용법

```powershell
# 이벤트 파싱 확인 (네트워크 없이 stdout 출력)
edr-lite.exe --dry-run

# Cloud Logging 전송 테스트 (이벤트 2건 전송 후 종료)
edr-lite.exe --config C:\edr\agent.toml --test

# 실제 수집 (관리자 권한, Ctrl+C로 종료)
edr-lite.exe --config C:\edr\agent.toml
```

## 로그 확인

로그는 세 곳에 나뉘어 쌓인다.

| 단계 | 위치 | 콘솔에서 보는 곳 |
|---|---|---|
| 에이전트가 보낸 원본 | Cloud Logging, 로그 이름 `lab_malware` | 로깅 > 로그 탐색기 |
| 싱크가 전달 | Pub/Sub 토픽 `edr-log-topic` | Pub/Sub > 토픽 |
| 검증 후 적재 | BigQuery 데이터셋 `edr_logs`의 `events` 테이블 | BigQuery |

분석에는 BigQuery `events`를 쓴다. 로그 탐색기에서 원본을 보려면 `_Default` 로그 싱크가 켜져 있어야 한다(`setup.ps1`이 비용 때문에 꺼 둔다).
켠 뒤부터 들어온 로그만 보이고, 테스트 중에는 러너가 켰다가 정리 단계에서 다시 끈다.

### BigQuery 쿼리 (BigQuery 콘솔의 쿼리 편집기에 입력)

세션별 이벤트 종류와 개수:

```sql
SELECT sid, kind, COUNT(*) AS n
FROM `<PROJECT_ID>.edr_logs.events`
WHERE recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY sid, kind
ORDER BY sid, n DESC
```

특정 세션의 최근 이벤트:

```sql
SELECT recv_time, seq, kind, severity
FROM `<PROJECT_ID>.edr_logs.events`
WHERE sid = '<세션 ID>'
ORDER BY recv_time DESC
LIMIT 50
```

경보 이력:

```sql
SELECT alert_time, sid, reason, detail
FROM `<PROJECT_ID>.edr_logs.alerts`
ORDER BY alert_time DESC
LIMIT 50
```

- 쿼리마다 `recv_time` 조건을 넣는다. 날짜별 파티션이라 읽는 양과 비용이 줄어든다.
- `payload`(JSON 원본)는 큰 열이라 필요할 때만 고른다. 이미지 로드(`image_load`)가 전체의 많은 부분을 차지하므로, 보기만 할 때는 `kind != 'image_load'`로 뺄 수 있다.
- 자주 보는 분류는 뷰로 만들어 둘 수 있다. 예: `CREATE VIEW ... AS SELECT ... FROM ...events WHERE kind = 'net'`

### 로그 탐색기 필터 (로그 탐색기의 쿼리 창에 입력, SQL이 아님)

```
logName="projects/<PROJECT_ID>/logs/lab_malware"
labels.sid="<세션 ID>"
labels.kind="net"
```

에이전트가 로그마다 `labels.sid`와 `labels.kind`를 붙여 보낸다. `severity>=WARNING`으로 etw 중지나 `etw_alive=false` heartbeat만 볼 수 있다.

## 감시와 경보

Function이 BigQuery 적재 시점과 주기 점검에서 판정한다. 같은 (세션, 사유) 경보는 30분에 한 번만 보낸다.

| 사유 | 조건 |
|---|---|
| `etw_stopped` | ETW 커널 세션이 외부 요인으로 중지됨 |
| `etw_not_alive` | heartbeat에 `etw_alive=false` |
| `heartbeat_silence` | 마지막 heartbeat(없으면 시작) 이후 `3 x heartbeat_secs` 초과 |
| `seq_gap` | heartbeat의 `seq`에서 수신한 고유 `seq`와 드롭 카운터를 뺀 값이 0보다 큼 |
| `invalid_event` | 형식·범위·크기 검증을 통과하지 못한 이벤트 (적재하지 않음) |

- 정상 종료(`agent_stop`)한 세션은 공백 경보에서 제외한다.
- 경보 이력은 BigQuery `alerts` 테이블에 남는다. 웹훅을 설정하지 않으면 Discord로 보내지 않고 이력만 남긴다.

## 키 유출 시 대응

회차별 재발급과 단기 토큰은 쓰지 않는다. 장기 키 한 개를 유지하므로 유출이 의심되면 즉시 폐기한다.

1. `gcp\revoke-key.ps1 -ProjectId <PROJECT_ID> -Action List`로 키 ID를 확인한다.
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

## 문제 해결

| 증상 | 원인과 해결 |
|---|---|
| 스크립트가 "이 시스템에서 스크립트를 실행할 수 없습니다"로 막힘 | 같은 관리자 창에서 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`를 먼저 실행한다. 실행하는 파일은 `00_run.ps1` 하나뿐이고 나머지 `.ps1`은 직접 실행하지 않는다 |
| `gcloud`나 `bq`를 찾을 수 없음 | SDK 설치 후 새 PowerShell 창을 연다. 러너는 `gcloud.cmd`를 직접 호출한다 |
| 한글이 깨지거나 구문 오류가 남 | `.ps1`이 "UTF-8 (BOM 포함)"으로 저장돼 있어야 한다. Windows PowerShell 5.1은 BOM 없는 UTF-8을 잘못 읽는다 |
| C6에서 "경로의 기존 파일을 서비스 계정 키로 쓸 수 없습니다" | 지정한 키 경로에 다른 파일이 있다. 파일 이름을 바꾸거나 다른 경로를 지정한다. 판정 설명에 어느 항목이 달랐는지 나온다 |
| D2에서 `토큰 발급 실패` | 키나 PC 시계 문제다. 키 파일과 `project_id`, 시간 동기화를 확인한다 |
| D2에서 `Cloud Logging HTTP 403/404` | 서비스 계정 권한이나 프로젝트 ID 문제다. 계정에 `Logs Writer` 역할이 있는지 확인한다 |
| 로그 탐색기에 로그가 없음 | (1) 전송이 아직 한 번도 성공하지 않았거나 (2) `_Default` 싱크가 꺼져 있다. BigQuery `events`를 먼저 확인하고, 원본을 보려면 `_Default`를 켠다. 로그 탐색기에 `CREATE VIEW` 같은 SQL을 넣으면 구문 오류가 난다. SQL은 BigQuery 편집기에 입력한다 |
| BigQuery에서 `Dataset ... was not found in location US` | 데이터셋이 없거나 위치가 다르다. 정리 단계(F5)에서 지웠다면 C 단계를 다시 실행해 만든다. 데이터셋이 서울에 있으면 쿼리 설정의 데이터 위치를 서울로 바꾼다 |
| 콘솔에서 Function이나 Scheduler가 안 보임 | 리전 필터를 서울 또는 "모든 리전"으로 바꾼다 |
| `setup.ps1`이 오래 걸리고 화면에 아무것도 안 나옴 | 러너가 출력을 파일로 모은다. Function 배포가 10~20분 걸리며, 진행은 콘솔의 Cloud Build 기록에서도 볼 수 있다 |
| 같은 세션에서 행이 일부 사라짐 | 세션 ID를 재사용했다. 새 ID를 쓴다 |

## 알려진 한계

- 사용자 모드 프로세스이므로 SYSTEM 권한 악성코드는 에이전트를 종료하거나 방해할 수 있다. heartbeat 공백과 `etw_stopped`로 탐지한다.
- 커널 ETW 세션 이름은 `logman query -ets`로 보인다.
- x64 게스트만 지원한다.
- `ts_ms`는 게스트 시계 기준이다. Cloud Logging 수신 시각(`recv_time`)을 기준으로 삼는다.
- 에이전트는 메모리 큐만 쓴다. 네트워크가 끊기면 큐가 차는 만큼 `dropped_queue`와 `dropped_send`가 늘고 해당 이벤트는 유실된다.
- 일반 PC는 분석용 VM보다 이벤트가 훨씬 많다. 이미지 로드를 켠 양 측정(E8) 값은 참고용이며 VM에서 다시 측정한다.
- GCP 구성·전송, 종단 간 시험, 정리 스크립트는 아직 끝까지 실행해 검증하지 않았다. 자동 테스트 범위는 [개발명세서.md](개발명세서.md)를 본다.

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `src\` | 에이전트 소스 (Rust) |
| `scripts\local-test\` | 원터치 테스트 러너 (`00_run.ps1`이 진입점, 나머지는 부품) |
| `scripts\harden.ps1` | 분석 VM 하드닝 |
| `gcp\setup.ps1`, `gcp\revoke-key.ps1` | GCP 구성과 키 관리 스크립트 |
| `gcp\functions\edr_monitor\` | 감시 Function 소스와 단위 테스트 |
| `gcp\schema.sql` | BigQuery 스키마 |
| `agent.example.toml` | 설정 예시 |
| `개발명세서.md` | 소스 구조, 모듈, 스키마, 보안 설계 |

`scripts\local-test\`의 파일은 이름 앞 번호가 역할과 불러오는 순서를 뜻한다.

| 파일 | 역할 |
|---|---|
| `00_run.ps1` | 진입점. 인자 처리, 단계 실행, 결과 요약 |
| `10_lib.ps1` | 공통 도구 (로그, 판정 기록, 외부 명령 실행, 에이전트 제어, GCP와 BigQuery 도구) |
| `15_prompts.ps1` | 실행에 필요한 값을 묻는 부분 |
| `20_stage-local.ps1` | P, A, B 단계 |
| `30_stage-gcp.ps1` | C, D 단계 |
| `40_stage-e2e.ps1` | E 단계 |
| `50_stage-cleanup.ps1` | F 단계 |

## 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 본다.
