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

> **검증 상태**
> - 실행해 확인한 것: 에이전트와 Function의 단위 테스트, 릴리스 빌드, 로컬 수집(`--dry-run`: 이벤트 필드, `seq`, heartbeat, ETW 중지 후 재시작), `gcp\setup.ps1`의 GCP 구성과 리소스 확인
> - 아직 통과하지 못한 것: 서비스 계정 키를 쓴 실제 전송(`--test`), BigQuery 도착 확인, 종단 간 시험(경보, 복구, 위조 로그 거부), 정리 단계
> - 위 항목은 코드를 작성했으나 끝까지 검증하지 못했으므로 처음 쓰는 환경에서는 오류가 날 수 있다. 반드시 이 용도 전용 GCP 프로젝트에서만 실행한다.
> - VC++ 런타임 없이 실행되는지(정적 링크)는 확인하지 않았다.

## 목차

1. [주요 특징](#주요-특징)
2. [수집 이벤트](#수집-이벤트)
3. [요구사항과 준비](#요구사항과-준비)
4. [빠른 시작: 원터치 테스트](#빠른-시작-원터치-테스트)
5. [수동 설치와 배포](#수동-설치와-배포)
6. [설정](#설정)
7. [사용법](#사용법)
8. [전송 동작](#전송-동작)
9. [로그 확인](#로그-확인)
10. [감시와 경보](#감시와-경보)
11. [키 유출 시 대응](#키-유출-시-대응)
12. [보안 설계와 수용한 위험](#보안-설계와-수용한-위험)
13. [문제 해결](#문제-해결)
14. [알려진 한계](#알려진-한계)
15. [저장소 구성](#저장소-구성)
16. [라이선스](#라이선스)

## 주요 특징

- 커널 ETW 기반 수집: 프로세스 시작/종료, 이미지 로드, TCP/UDP 연결
- 직접 전송: 게스트가 Cloud Logging `entries.write`를 호출한다. 서비스 계정에는 `Logs Writer`만 부여해 쓰기 전용으로 둔다
- 단방향: 에이전트가 원격 명령을 받는 기능이 없다
- 수집 중단 탐지: heartbeat, 이벤트 일련번호(`seq`), ETW 세션 중지 감시와 자동 재시작. 판정과 경보는 Google Function이 맡는다
- TLS 1.3 전용, 에이전트에 내장한 공개 루트 CA만 신뢰한다 (OS 인증서 저장소 미사용)
- 서비스 계정 키는 메모리에만 보관하고, 설정에 따라 로드 직후 디스크의 키 파일을 지운다

## 수집 이벤트

| kind | 내용 |
|---|---|
| `proc_start` / `proc_stop` | 프로세스 시작 / 종료 |
| `proc_existing` | 에이전트 시작 시점에 이미 실행 중이던 프로세스 |
| `image_load` | 프로세스가 로드한 모듈 경로 (`collect_image_loads`, 기본 켜짐) |
| `net` | TCP connect/accept (IPv4, IPv6), UDP send (`collect_network`, 기본 켜짐) |
| `heartbeat` | 에이전트 상태와 ETW 세션 상태 |
| `etw_stopped` / `etw_restarted` | ETW 세션 중지 감지 / 자동 재시작 |
| `agent_start` / `agent_stop` | 에이전트 시작 / 종료 |

모든 이벤트는 공통 필드 `v`, `sid`, `seq`, `ts_ms`, `kind`를 가지고, `kind`별 필드가 같은 단계에 이어진다. 필드 상세는 [개발명세서.md](개발명세서.md)를 본다.

수집 방식의 세부 사항:

- 이미 로드되어 있던 모듈(시작 시점의 DCStart)은 수집하지 않고, 새로 로드되는 모듈만 수집한다.
- UDP는 (프로세스, 대상 주소, 대상 포트)가 같으면 60초 안에는 한 번만 기록한다. ICMP(ping)는 수집하지 않는다.
- 에이전트 자신의 PID는 `net`과 `image_load`에서 제외한다(전송 연결이 다시 기록되는 피드백 루프 방지).
- 문자열 길이 상한: `image` 1024자, `cmdline` 8192자, `path` 1024자. 넘으면 끝에 `…[truncated]`가 붙고 제어문자는 공백으로 바뀐다.
- ETW 세션이 외부에서 중지되면 `etw_stopped`를 기록하고 자동으로 다시 시작한다. 시작에 실패하면 1, 2, 5, 10초 간격(마지막 값 반복)으로 재시도하고, 그때마다 `etw_stopped`(detail `restart failed`)를 기록한다.

## 요구사항과 준비

### 빌드와 테스트를 실행하는 PC

| 항목 | 설명 |
|---|---|
| OS | Windows 11 x64, 관리자 권한 PowerShell (ETW와 일부 테스트에 필요) |
| Rust | MSVC 툴체인(`rustup`)과 Visual Studio Build Tools |
| Python | Python 3 (Function 단위 테스트용, 추가 패키지 불필요. Function 런타임은 3.12) |
| Google Cloud SDK | `gcloud`와 `bq` 명령 (GCP 단계를 실행할 때만) |
| GCP | 이 용도 전용 프로젝트 하나, 결제 연결, 프로젝트 소유자 권한 계정 |
| Discord | (선택) 경보를 받을 테스트 서버의 웹훅. 없으면 경보를 BigQuery `alerts`에만 기록한다 |

### 처음 한 번 하는 준비

1. 위 도구를 설치한 뒤 **새 PowerShell 창**을 연다(설치한 도구가 PATH에 잡히도록).
2. GCP 단계를 실행할 때는 로그인한다.

```powershell
gcloud auth login
```

3. 관리자 PowerShell 창에서 스크립트 실행 정책을 이 창에만 허용한다(창을 닫으면 원래대로 돌아간다).

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 분석 VM

Windows 11 x64, 관리자(SYSTEM) 권한 실행, `logging.googleapis.com`과 `oauth2.googleapis.com`의 443 포트에 접근 가능해야 한다. x64 게스트만 지원한다.

## 빠른 시작: 원터치 테스트

`scripts\local-test\00_run.ps1` 하나로 빌드, 단위 테스트, 로컬 수집 확인, GCP 구성, 전송 확인, 종단 간 시험, 정리까지 순서대로 실행하고 항목별 결과(PASS / FAIL / SKIP / MANUAL)를 표로 보여 준다. 필요한 값은 실행 중에 물어본다. 직접 실행하는 파일은 `00_run.ps1` 하나뿐이다.

### 1. 로컬 단계만 먼저 실행 (GCP에 접속하지 않음)

```powershell
cd <저장소 폴더>
.\scripts\local-test\00_run.ps1 -LocalOnly
```

필요한 도구는 `cargo`와 `python`이고, 단계 B(ETW 수집)는 관리자 권한이 필요하다.

### 2. 전체 실행 (GCP 단계 포함)

```powershell
.\scripts\local-test\00_run.ps1 -KeyPath C:\edr\sa-key.json
```

실행하면 아래를 차례로 묻는다. 인자로 이미 준 값은 다시 묻지 않는다.

| 질문 | 설명 |
|---|---|
| 실행 범위 | 전체(P~F) 또는 로컬만(P, A, B) |
| GCP 테스트 전용 프로젝트 ID | 6~30자, 소문자로 시작, 소문자/숫자/하이픈, 하이픈으로 끝날 수 없음 |
| 리전, BigQuery 위치 | 기본값 `asia-northeast3`(서울). Enter로 받는다 |
| Discord 웹훅 주소 | 입력이 화면에 표시되지 않는다. 비우면 알림 없이 진행. 환경변수 `EDR_WEBHOOK_URL`이 있으면 그 값을 쓴다 |
| 서비스 계정 키 경로 | 저장소 밖 경로만 허용. 기본 `C:\edr\sa-key.json` |
| 설정 파일 경로 | 기본 `C:\edr\agent.toml` |
| 이미지 로드 측정 시간 | 분 단위(1~30, 기본 3). E8에서 쓴다 |
| 최종 확인 | 프로젝트 ID를 그대로 입력해야 진행 (다른 입력은 취소) |

| 인자 | 설명 |
|---|---|
| `-LocalOnly` | 질문 없이 로컬 단계(P, A, B)만 실행 |
| `-Stages` | 실행할 단계(`P`, `A`, `B`, `C`, `D`, `E`, `F`). 예: `-Stages C,D,E,F`. 순서와 상관없이 P에서 F 순서로 실행 |
| `-ProjectId`, `-Region`, `-BqLocation`, `-KeyPath`, `-ConfigPath`, `-ImageLoadMinutes` | 값을 미리 주면 다시 묻지 않는다 |
| `-SessionPrefix` | 세션 이름 접두사(기본 `run-test`). 뒤에 월일시분이 붙고, 단계별 접미사(`-d2`, `-e1` 등)가 더해진다 |
| `-DryRunSeconds` | B 단계에서 에이전트를 돌려 두는 시간(초, 기본 40, 25초 미만은 25초로 올림) |
| `-RepoRoot` | 저장소 루트(기본: 스크립트 위치에서 두 단계 위) |
| `-ContinueOnFail` | 한 단계에 FAIL이 있어도 다음 단계를 계속 실행 |
| `-Yes` | 최종 확인 질문을 생략. F5 데이터셋 삭제 질문도 건너뛴다(삭제하지 않음). GCP를 바꾸므로 주의 |
| `-DeleteArtifacts` | 끝나면 로그 폴더의 수집 파일(`*.ndjson`)을 삭제 |

### 단계와 항목

| 단계 | 항목 | 하는 일 |
|---|---|---|
| P 준비 | P1~P6 | 관리자 권한, 도구 설치, gcloud 로그인, 프로젝트 접근, 웹훅 준비 안내(수동), 세션 이름 |
| A 자동 테스트 | A1~A3 | `cargo test`, `python -m unittest`(Function), `cargo build --release` |
| B 로컬 수집 | B1~B8 | `--dry-run` 시작, 무해한 활동 생성, Ctrl+C 정상 종료, 종류별 집계와 분량, 필드와 `seq`, heartbeat, 자기 PID 제외, ETW 세션 중지 후 자동 재시작 |
| C GCP 구성 | C1~C7 | 스크립트 확인, `setup.ps1` 실행, Function/Scheduler/싱크 확인, BigQuery 테이블 확인, `_Default` 싱크 켜기, 서비스 계정 키 준비, 월 예산 알림(수동) |
| D 전송 확인 | D1~D7 | `agent.toml` 작성, `--test` 전송, BigQuery 도착 확인, Pub/Sub 디버그 구독(자동으로 만들지 않음), 실패 시나리오 3개(없는 프로젝트, 키 파일 오류, 전송 차단) |
| E 종단 간 | E1~E8 | 수집 경로, ETW 중지 경보, 경보 중복 방지, heartbeat 공백 경보, 정상 종료는 경보 없음, 전송 중단과 복구, 위조 로그 거부, 이미지 로드를 켠 양 측정 |
| F 정리 | F1~F6 | 에이전트와 방화벽 규칙 정리, 키 폐기와 파일 삭제, 디버그 구독 삭제, `_Default` 싱크 끄기, 데이터 정리, 임시 파일 안내 |

- 전체 실행은 대략 20~40분 걸리고 소액의 GCP 비용이 발생할 수 있다.
- C 단계의 `setup.ps1`은 Function 배포 때문에 10~20분 걸린다. 출력이 화면에 나오지 않고 끝난 뒤 로그 폴더(`C2-setup.out.txt`, `C2-setup.err.txt`)에 저장된다. 진행은 콘솔의 Cloud Build 기록에서도 볼 수 있다.
- 한 단계에 FAIL이 있으면 이후 단계는 건너뛴다(`-ContinueOnFail`로 변경). GCP를 변경한 실행은 중간에 멈추거나 실패해도 마지막에 정리(F)를 시도한다.
- 월 예산 알림(C7)과 Discord 도착 확인은 사람이 한다. 웹훅을 입력한 경우에만 도착 여부를 묻고, 결과는 MANUAL로 표시될 수 있다.
- 종료 코드: FAIL이 하나라도 있으면 1, 없으면 0, 최종 확인에서 취소하면 2

### 결과와 로그

- 로그 폴더: `%TEMP%\edr-test-<시각>\` (`run.log`, `summary.txt`, `results.csv`, 명령별 출력)
- 로그 폴더의 `*.ndjson`에는 프로세스 명령줄이 들어 있어 경로, 사용자 이름, 인자에 든 값이 섞일 수 있다. 필요 없으면 `-DeleteArtifacts` 또는 직접 삭제한다.

### 러너가 하는 시스템 변경

- 악성코드를 실행하지 않는다. 무해한 활동(`cmd /c echo`, `curl`, DNS 조회)만 만든다.
- 이 실행이 시작한 에이전트만 PID로 종료하고, 이 실행이 만든 ETW 세션만 지운다.
- D7과 E5에서 에이전트 실행 파일 하나만 막는 아웃바운드 방화벽 규칙 `edr-test-block`을 잠시 만들었다가 지운다(관리자 권한 필요).
- C5에서 `_Default` 로그 싱크를 켜고 F4에서 다시 끈다.
- E6에서 형식이 틀린 위조 로그 한 건을, 로그인한 gcloud 계정으로 Cloud Logging에 기록한다. 토큰은 변수에만 두고 파일과 로그에 남기지 않는다.
- D1에서 지정한 경로에 `agent.toml`이 이미 있으면 `.bak-<시각>`으로 옮기고, F에서 지우고 되돌린다.
- 키 경로에 이미 `service_account` 키 파일(같은 프로젝트)이 있으면 재사용한다. 이 경우 이번 실행이 만든 키가 아니므로 F가 폐기하지 않는다. 쓰고 나서 직접 정리한다.
- 키, 웹훅 주소, 토큰은 화면과 로그에 남기지 않는다. 웹훅 주소는 `setup.ps1`을 실행하는 동안에만 환경변수로 전달하고 바로 지운다.
- F5(데이터셋 `edr_logs` 삭제)는 프로젝트 ID를 직접 입력해야 진행하고, Enter만 누르면 지우지 않는다. 프로젝트 삭제는 하지 않는다.
- 테스트 중 이 PC의 프로세스 이벤트가 GCP로 업로드된다. 민감한 작업은 닫고 진행한다.

## 수동 설치와 배포

원터치 테스트를 쓰지 않고 직접 배포할 때의 순서다.

### 1. 빌드

```powershell
cargo build --release
```

결과물은 `target\release\edr-lite.exe`다.

### 2. GCP 구성 (`gcp\setup.ps1`)

```powershell
.\gcp\setup.ps1 -ProjectId <PROJECT_ID>
```

| 인자 | 기본값 | 설명 |
|---|---|---|
| `-ProjectId` | (필수) | 전용 GCP 프로젝트 ID |
| `-Region` | `asia-northeast3` | Function과 Scheduler의 리전 |
| `-BqLocation` | `asia-northeast3` | BigQuery 데이터셋 위치 (한 번 만들면 바꿀 수 없다) |
| `-LogName` | `lab_malware` | 싱크가 전달할 로그 이름 (에이전트의 `log_name`과 같아야 한다) |
| `-HeartbeatSecs` | `10` | Function의 `HEARTBEAT_SECS` (에이전트의 `heartbeat_secs` 이상) |
| `-WatchdogSchedule` | `*/2 * * * *` | watchdog 호출 주기(cron) |
| `-SkipSecret` | 끔 | 웹훅 Secret을 만들지 않는다 (경보를 Discord로 보내지 않음) |

7단계로 진행하며 다시 실행해도 이미 있는 리소스는 건너뛴다.

1. API 활성화(Logging, BigQuery, Pub/Sub, Cloud Functions, Cloud Run, Eventarc, Cloud Build, Cloud Scheduler, Secret Manager, Artifact Registry, Compute)
2. 서비스 계정 3개와 역할
3. Pub/Sub 토픽 `edr-log-topic`, BigQuery 데이터셋 `edr_logs`와 테이블 `events`, `alerts`(`gcp\schema.sql`)
4. Discord 웹훅을 Secret Manager(`edr-discord-webhook`)에 저장. 환경변수 `EDR_WEBHOOK_URL`이 있으면 그 값을, 없으면 숨김 입력을 쓴다. 명령줄 인자로는 받지 않는다
5. 로그 싱크 `edr-log-sink`(지정한 로그 이름만 토픽으로 전달)를 만들고 `_Default` 싱크를 비활성화
6. Function 2개 배포: `edr-ingest`(Pub/Sub 트리거), `edr-watchdog`(HTTP, 인증 필요). Python 3.12, 메모리 256Mi, 최대 인스턴스 5
7. Cloud Scheduler 작업 `edr-watchdog-job`(OIDC 인증으로 watchdog 호출)

| 서비스 계정 | 역할 |
|---|---|
| `edr-logwriter` (에이전트 키 소유) | `roles/logging.logWriter` |
| `edr-monitor-fn` (Function 실행) | `roles/bigquery.dataEditor`, `roles/bigquery.jobUser`, `roles/eventarc.eventReceiver`, Secret 접근, Function 호출 |
| `edr-scheduler` (Scheduler 호출) | watchdog 호출(`roles/run.invoker`) |

기본 Compute 서비스 계정에 빌드 역할(`roles/cloudbuild.builds.builder`)을 부여하는 데 실패하면 경고만 하고 계속한다. 배포 단계가 빌드 권한 오류로 실패하면 이 역할을 직접 부여한다.

월 예산 알림(약 5,000원)은 콘솔(결제 > 예산 및 알림)에서 직접 만든다. 예산 알림은 경고만 하고 지출을 막지 않는다.

### 3. 서비스 계정 키 관리 (`gcp\revoke-key.ps1`)

| 동작 | 명령 |
|---|---|
| 키 목록 | `.\gcp\revoke-key.ps1 -ProjectId <ID> -Action List` |
| 키 발급 | `.\gcp\revoke-key.ps1 -ProjectId <ID> -Action New -OutFile <저장소 밖 경로>` |
| 키 폐기 | `.\gcp\revoke-key.ps1 -ProjectId <ID> -Action Revoke -KeyId <키 ID> [-DisableAccount]` |

- `New`는 저장소 안 경로나 이미 있는 파일에는 쓰지 않고, 만든 파일의 접근을 현재 사용자로 제한한다.
- 기본 대상 계정은 `edr-logwriter`이고 `-ServiceAccountName`으로 바꿀 수 있다.

### 4. 분석 VM 배치

`C:\edr\`에 `edr-lite.exe`, `agent.toml`, `sa-key.json`을 복사한다. `agent.toml`은 `agent.example.toml`을 복사해 채운다.

### 5. OS 하드닝 (`scripts\harden.ps1`, 관리자 PowerShell)

```powershell
.\scripts\harden.ps1 -EdrDir C:\edr -SampleUser analyst -CreateSampleUser
```

- `-CreateSampleUser`를 주면 제한 계정을 만들고 **임시 비밀번호를 화면에 출력**한다(스냅샷 후 폐기).
- `C:\edr`를 SYSTEM과 Administrators 전용으로 잠그고, `*.key`와 `*.json` 파일은 SYSTEM 전용으로 잠근다.
- 에이전트를 SYSTEM 권한, 부팅 시 자동 실행 예약 작업 `WindowsTelemetryService`로 등록한다(실패 시 1분 간격으로 재시작). `edr-lite.exe`가 `C:\edr`에 없으면 중단한다.
- 등록만 하고 시작하지는 않으므로 `Start-ScheduledTask -TaskName WindowsTelemetryService`로 직접 시작한다.

### 6. 전송 확인

키가 SYSTEM 전용이므로 `--test`는 SYSTEM 권한으로 실행한다(작업 스케줄러에서 SYSTEM 계정으로 한 번 실행하는 방식). `wipe_sa_key = true`이면 테스트도 키 파일을 지우므로, 테스트 중에는 끄거나 키를 다시 복사할 준비를 한다.

### 7. 결과 확인과 스냅샷

BigQuery `edr_logs.events`에 이벤트가 들어오고 경보 채널이 동작하는지 본 뒤 VM 스냅샷을 찍는다. 키 파일은 스냅샷에 포함되므로 복원할 때마다 되살아난다. 제한 계정으로 샘플을 실행하고, 분석이 끝나면 스냅샷을 복원한다.

### 폴더 배치

| 용도 | 위치 | 이유 |
|---|---|---|
| 소스, 스크립트 | 저장소 폴더 | 코드만 둔다 |
| 서비스 계정 키 | `C:\edr\sa-key.json` | 저장소 밖에 둔다. git에 올라가는 사고를 막는다 |
| 에이전트 설정 | `C:\edr\agent.toml` | 키 경로와 세션 ID가 들어 있다 |
| 테스트 결과 | `%TEMP%\edr-test-<시각>\` | 러너가 자동으로 만든다 |

`.gitignore`가 `/target`, `agent.toml`, `sa-key*.json`, `*-sa-key.json`, `*.key`를 제외한다.

### 리전

- 리전은 GCP 리소스가 놓이는 지역이다. 기본값은 서울(`asia-northeast3`)이다.
- Function과 Scheduler는 `-Region`, BigQuery 데이터셋은 `-BqLocation`에 만들어진다. Cloud Logging과 Pub/Sub은 리전을 고르지 않는다.
- 콘솔에서 Function이나 Scheduler가 안 보이면 화면 위쪽 리전 필터를 해당 리전 또는 "모든 리전"으로 바꾼다.

## 설정

`agent.example.toml`을 복사해 `agent.toml`로 만들고 값을 채운다. 설정 파일은 빌드와 무관하며 실행할 때 `--config`로 지정한다. 알 수 없는 키가 있으면 에이전트가 시작하지 않는다(이전 릴레이 방식의 `relay_url` 같은 키도 같다).

| 키 | 필수 | 기본값 | 범위와 설명 |
|---|---|---|---|
| `gcp_project_id` | 예 | - | 6~30자, 소문자로 시작, `[a-z0-9-]`, 하이픈으로 끝날 수 없음 |
| `sa_key_path` | 예 | - | 서비스 계정 키(JSON) 경로. `Logs Writer`만 가진 계정을 쓴다 |
| `session_id` | 예 | - | 분석 회차 ID. 모든 이벤트의 `sid`. 1~64자 `[A-Za-z0-9_-]` |
| `log_name` | 아니오 | `lab_malware` | Cloud Logging 로그 이름. 1~100자 `[A-Za-z0-9._-]` |
| `batch_max_events` | 아니오 | 500 | 한 번에 보내는 최대 이벤트 수, 1~1000 |
| `batch_max_bytes` | 아니오 | 524288 | 한 번에 보내는 최대 바이트, 4096~4194304 |
| `flush_interval_ms` | 아니오 | 500 | 배치를 비우는 주기(ms), 100~60000 |
| `queue_capacity` | 아니오 | 50000 | 메모리 큐 크기, 100~1000000 |
| `heartbeat_secs` | 아니오 | 10 | heartbeat 주기(초), 1~300 |
| `collect_image_loads` | 아니오 | `true` | 이미지 로드 수집. 이벤트가 많아 비용이 늘어난다 |
| `collect_network` | 아니오 | `true` | 네트워크 수집 |
| `trace_name` | 아니오 | 자동 | ETW 세션 이름. 1~128자 `[A-Za-z0-9 _-]`. 생략하면 `WinTelemetry-<16진수>-<pid>` 형태로 생성 |
| `wipe_sa_key` | 아니오 | `false` | `true`면 키를 메모리에 올린 직후 키 파일을 0으로 덮어쓰고 삭제 |

- `heartbeat_secs`를 바꾸면 Function의 `HEARTBEAT_SECS`도 같은 값 이상으로 맞춘다(`setup.ps1 -HeartbeatSecs`).
- `wipe_sa_key`는 SSD와 저널링 파일 시스템에서 완전 삭제를 보장하지 않는다. 일상적인 탈취 난이도를 높이는 수준이다.

### 세션 ID 규칙

- 길이 1~64자, 영문 대소문자, 숫자, `-`, `_`만 쓴다. 규칙에 맞지 않으면 에이전트가 시작하지 않고 Function도 그 이벤트를 거부한다.
- 같은 ID를 재사용하지 않는다. 순번(`seq`)이 1부터 다시 시작해 이전 기록과 섞이고, BigQuery 적재가 `<sid>-<seq>`를 중복 방지 키로 쓰므로 1분 안에 재시작하면 일부 행이 버려질 수 있다.
- 의미 있는 이름이 좋다. 예: `sample-emotet-20261024-01`
- 게스트가 정하는 값이므로 인증 근거로 쓰지 않는다.

## 사용법

```powershell
# 이벤트 파싱 확인 (설정 없이, 네트워크 없이 stdout에 NDJSON 출력)
edr-lite.exe --dry-run

# Cloud Logging 전송 테스트 (agent_start, agent_stop 2건 전송 후 종료. ETW 미사용)
edr-lite.exe --config C:\edr\agent.toml --test

# 실제 수집 (관리자 권한, Ctrl+C로 종료)
edr-lite.exe --config C:\edr\agent.toml

# 버전 확인
edr-lite.exe --version
```

| 인자 | 설명 |
|---|---|
| `--config <경로>`, `-c <경로>` | 설정 파일. `--dry-run`이 아니면 필수 |
| `--dry-run` | 설정 없이 stdout에 출력. 전송하지 않는다 |
| `--test` | 전송 테스트만 실행 |
| `--version` | 버전 출력 |

- 종료 코드: 정상 0, 인자 오류 2, 치명적 오류(설정 오류, 키 오류, 전송 실패, ETW 시작 불가 등) 1
- 실행 상태 메시지는 stderr로 나온다(`[edr] ETW 세션: ...`, `[edr] 수집 시작 (session=..., pid=...)`, `[edr] 종료 중...`).
- Ctrl+C로 종료하면 ETW 세션을 정리하고 `agent_stop`(reason `signal`)을 보낸 뒤 종료한다. 큐에 남은 이벤트를 보내기 위해 최대 10초 기다린다.

## 전송 동작

1. 이벤트를 메모리 큐에 넣는다. 큐가 가득 차면 이벤트를 버리고 `dropped_queue`를 올린다. `seq`는 이벤트를 만들 때 부여하므로 버려진 이벤트는 `seq` 공백으로 남는다.
2. 송신 스레드가 `batch_max_events`, `batch_max_bytes`, `flush_interval_ms` 중 먼저 도달한 조건에서 배치를 보낸다.
3. 서비스 계정 키로 JWT를 RS256으로 서명해 `oauth2.googleapis.com`에서 접근 토큰(범위 `logging.write`)을 받아 `logging.googleapis.com`의 `entries:write`를 호출한다. 서버가 401을 돌려주면 토큰을 다시 받아 한 번만 재시도한다.
4. 전송에 실패하면 250, 1000, 3000ms 간격으로 3번 재시도하고, 그래도 실패하면 그 배치를 버리고 `dropped_send`를 올린다. 두 카운터는 heartbeat로 보고된다.
5. 연결 시간 제한 5초, 전체 시간 제한 15초. 프록시 환경변수를 쓰지 않고 리다이렉트를 따르지 않는다.

Cloud Logging 항목 구조:

```
logName   projects/<프로젝트>/logs/<log_name>
resource  global (project_id 라벨)
항목      jsonPayload = 이벤트 JSON 전체
          severity    = etw_stopped는 ERROR, etw_alive=false인 heartbeat는 WARNING, 그 외 INFO
          labels      = sid, kind
          insertId    = <sid>-<seq>
```

로그 시각(`timestamp`)은 지정하지 않아 Cloud Logging 수신 시각이 기록된다. 게스트 시각은 `ts_ms`에만 있다.

## 로그 확인

로그는 세 곳에 나뉘어 쌓인다.

| 단계 | 위치 | 콘솔에서 보는 곳 |
|---|---|---|
| 에이전트가 보낸 원본 | Cloud Logging, 로그 이름 `lab_malware` | 로깅 > 로그 탐색기 |
| 싱크가 전달 | Pub/Sub 토픽 `edr-log-topic` | Pub/Sub > 토픽 |
| 검증 후 적재 | BigQuery 데이터셋 `edr_logs`의 `events` 테이블 | BigQuery |

분석에는 BigQuery `events`를 쓴다. 로그 탐색기에서 원본을 보려면 `_Default` 로그 싱크가 켜져 있어야 한다(`setup.ps1`이 비용 때문에 꺼 둔다). 켠 뒤부터 들어온 로그만 보이고, 테스트 중에는 러너가 켰다가 정리 단계에서 다시 끈다. 리소스 생성 같은 감사 로그는 `_Default`와 관계없이 항상 저장된다.

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

- `events` 테이블 열: `recv_time`(Cloud Logging 수신 시각), `sid`, `seq`, `kind`, `ts_ms`, `severity`, `pid`, heartbeat 전용 `dropped_queue`, `dropped_send`, `etw_alive`, `etw_restarts`, 그리고 이벤트 전체를 담은 `payload`(JSON). `cmdline`, `image`, `dst` 같은 나머지 필드는 `payload` 안에만 있다.
- `recv_time` 기준 일 단위 파티션이고 `sid`, `kind`로 클러스터링되어 있다. 쿼리마다 `recv_time` 조건을 넣으면 읽는 양과 비용이 줄어든다.
- `payload`는 큰 열이라 필요할 때만 고른다. 이미지 로드가 전체의 많은 부분을 차지하므로 보기만 할 때는 `kind != 'image_load'`로 뺄 수 있다.
- 자주 보는 분류는 BigQuery 편집기에서 뷰로 만들어 둘 수 있다. 예: `CREATE VIEW ... AS SELECT ... FROM ...events WHERE kind = 'net'`

### 로그 탐색기 필터 (로그 탐색기의 쿼리 창에 입력, SQL이 아님)

```
logName="projects/<PROJECT_ID>/logs/lab_malware"
labels.sid="<세션 ID>"
labels.kind="net"
```

`severity>=WARNING`으로 ETW 중지나 `etw_alive=false` heartbeat만 볼 수 있다.

## 감시와 경보

Function이 이벤트를 적재할 때와 Scheduler가 주기적으로 호출할 때 판정한다.

### 적재 검증 (`edr-ingest`)

게스트가 보낸 값은 신뢰하지 않는다. 아래를 통과하지 못하면 적재하지 않고 `invalid_event` 경보(사유 코드 포함)를 보낸다.

- `kind`가 허용 목록(위 이벤트 종류 10가지)에 있을 것
- `sid`가 `[A-Za-z0-9_-]` 1~64자, `seq`가 1 이상 10^12 이하 정수, `ts_ms`가 0 이상 정수, `v`가 1
- heartbeat는 `dropped_queue`, `dropped_send`, `etw_restarts`가 0 이상 정수이고 `etw_alive`가 불리언
- `pid`가 있으면 0 이상 2^32 이하 정수
- 이벤트 크기가 64KiB 이하

경보 메시지에는 검증된 값(세션 ID, 숫자, 고정 사유 코드)만 넣고 게스트가 정한 임의 문자열은 넣지 않는다.

### 경보 조건

| 사유 | 조건 | 판정 위치 |
|---|---|---|
| `etw_stopped` | ETW 커널 세션이 외부 요인으로 중지됨 | 적재 시 |
| `etw_not_alive` | heartbeat에 `etw_alive=false` | 적재 시 |
| `invalid_event` | 위 검증을 통과하지 못한 이벤트 (적재하지 않음) | 적재 시 |
| `heartbeat_silence` | 마지막 heartbeat(없으면 시작) 이후 `3 x HEARTBEAT_SECS` 초과 | 주기 점검 |
| `seq_gap` | 마지막 heartbeat가 60초 이상 지난 세션에서 (heartbeat의 `seq` - 수신한 고유 `seq` 수 - `dropped_queue` - `dropped_send`)가 0보다 큼 | 주기 점검 |

- 주기 점검은 최근 `LOOKBACK_HOURS`(기본 24시간)의 이벤트에서 세션별로 마지막 `agent_start` 이후만 본다. `agent_stop`이 있는 세션은 건너뛴다.
- 같은 (세션, 사유) 경보는 `ALERT_REPEAT_MINUTES`(기본 30분)에 한 번만 보낸다. 정상 종료하지 않은 세션은 조회 범위를 벗어날 때까지 30분마다 반복될 수 있다.
- 경보 이력은 BigQuery `alerts`에 남는다. 웹훅이 없으면 Discord로 보내지 않고 이력만 남긴다. Discord 전송이 실패하면 이력을 남기지 않아 다음 기회에 다시 시도한다.
- 메시지 형식: `[EDR] <사유> | sid=<세션> | <상세>`

### Function 환경변수 (모두 선택)

| 이름 | 기본값 | 설명 |
|---|---|---|
| `BQ_DATASET` | `edr_logs` | 데이터셋 |
| `EVENTS_TABLE`, `ALERTS_TABLE` | `events`, `alerts` | 테이블 |
| `HEARTBEAT_SECS` | 10 | 에이전트 `heartbeat_secs` 이상으로 맞춘다 |
| `LOOKBACK_HOURS` | 24 | 주기 점검 조회 범위 |
| `ALERT_REPEAT_MINUTES` | 30 | 같은 경보를 다시 보내기까지의 간격 |
| `DISCORD_WEBHOOK_URL` | 없음 | Secret Manager에서 주입. 코드와 로그에 적지 않는다 |

## 키 유출 시 대응

회차별 재발급과 단기 토큰은 쓰지 않는다. 장기 키 한 개를 유지하므로 유출이 의심되면 즉시 폐기한다.

1. `gcp\revoke-key.ps1 -ProjectId <PROJECT_ID> -Action List`로 키 ID를 확인한다.
2. `-Action Revoke -KeyId <ID> -DisableAccount`로 키를 삭제하고 서비스 계정을 비활성화한다.
3. 의심 시점 이후 `events`를 검토한다. 위조 로그는 분석 자료로 보고 증거로 쓰지 않는다.
4. 서비스 계정을 다시 활성화(`gcloud iam service-accounts enable <계정 이메일> --project=<PROJECT_ID>`)하고 `-Action New`로 새 키를 발급해 분석 VM에 복사한 뒤 에이전트를 재시작한다.

## 보안 설계와 수용한 위험

| 항목 | 내용 |
|---|---|
| 자격증명 | 쓰기 전용(`Logs Writer`) 서비스 계정, EDR 전용 프로젝트, 키는 메모리에만 보관, `wipe_sa_key`로 디스크 키 삭제, `harden.ps1`로 SYSTEM 전용 파일 권한 |
| 통신 | TLS 1.3 전용, 내장 루트 CA만 신뢰, 프록시 환경변수 미사용, 리다이렉트 금지, 키 파일의 `type`은 `service_account`여야 하고 토큰 엔드포인트는 `https://oauth2.googleapis.com/`만 허용 |
| 로그 삭제 | 서비스 계정에 읽기·삭제 권한이 없다. `_Default` 싱크를 끄고 BigQuery 파티션을 30일 후 만료시킨다 |
| 비용 | 월 5,000원 내외를 목표로 하며 위험을 수용한다. 허용한 `kind` 외 이벤트는 적재하지 않는다. 예산 알림은 경고만 하고 지출을 막지 않는다 |
| 수용한 위험 | 장기 키가 게스트에 있고 스냅샷에도 남는다. 분석 VM의 인터넷 통신은 차단하지 않는다(VPN 경유는 방화벽 정책에서 처리). 키가 유출되면 위조 로그가 들어올 수 있고, 위조 heartbeat로 생존 판정을 속일 수 있으므로 호스트 측 증거(PCAP 등)와 교차 검증한다 |

## 문제 해결

| 증상 | 원인과 해결 |
|---|---|
| "이 시스템에서 스크립트를 실행할 수 없습니다" | 같은 관리자 창에서 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`를 먼저 실행한다. 직접 실행하는 파일은 `00_run.ps1` 하나뿐이다 |
| `gcloud`나 `bq`를 찾을 수 없음 | SDK 설치 후 새 PowerShell 창을 연다. 러너는 `gcloud.cmd`를 직접 호출한다 |
| 한글이 깨지거나 구문 오류가 남 | 한글이 든 `.ps1`은 "UTF-8 (BOM 포함)"으로 저장돼 있어야 한다. Windows PowerShell 5.1은 BOM 없는 UTF-8을 잘못 읽는다 |
| `--config <path> 또는 --dry-run 이 필요합니다` | `--config`를 주지 않았다 |
| `설정 파싱 실패 ... unknown field` | 설정에 없는 키가 있다(예: 이전 릴레이 방식의 `relay_url`, `proxy`). 키 이름을 `agent.example.toml`과 맞춘다 |
| `ETW 커널 세션 시작 실패 (관리자 권한 필요)` | 관리자 권한으로 실행한다 |
| C6에서 "경로의 기존 파일을 서비스 계정 키로 쓸 수 없습니다" | 지정한 키 경로에 `service_account` 키가 아니거나 다른 프로젝트의 파일이 있다. 판정 설명에 달랐던 항목(JSON 읽기 실패, `type`, `project_id`)이 나온다. 파일 이름을 바꾸거나 다른 경로를 지정한다 |
| D2에서 `토큰 발급 실패` | 키나 PC 시계 문제다. 키 파일과 `project_id`, 시간 동기화를 확인한다 |
| D2에서 `Cloud Logging HTTP 403/404` | 서비스 계정 권한이나 프로젝트 ID 문제다. 계정에 `Logs Writer` 역할이 있는지 확인한다 |
| 로그 탐색기에 로그가 없음 | (1) 전송이 아직 한 번도 성공하지 않았거나 (2) `_Default` 싱크가 꺼져 있다. BigQuery `events`를 먼저 확인하고, 원본을 보려면 `_Default`를 켠다. 로그 탐색기에 `CREATE VIEW` 같은 SQL을 넣으면 구문 오류가 난다. SQL은 BigQuery 편집기에 입력한다 |
| BigQuery에서 `Dataset ... was not found in location US` | 데이터셋이 없거나 위치가 다르다. 정리 단계(F5)에서 지웠다면 C 단계를 다시 실행해 만든다. 데이터셋이 있으면 쿼리 설정의 데이터 위치를 데이터셋 위치로 바꾼다 |
| 콘솔에서 Function이나 Scheduler가 안 보임 | 리전 필터를 해당 리전 또는 "모든 리전"으로 바꾼다 |
| `setup.ps1`이 오래 걸리고 화면에 아무것도 안 나옴 | 러너가 출력을 파일로 모은다. Function 배포가 10~20분 걸리며, 진행은 콘솔의 Cloud Build 기록에서도 볼 수 있다 |
| 같은 세션에서 행이 일부 사라짐 | 세션 ID를 재사용했다. 새 ID를 쓴다 |

## 알려진 한계

- 사용자 모드 프로세스이므로 SYSTEM 권한 악성코드는 에이전트를 종료하거나 방해할 수 있다. heartbeat 공백과 `etw_stopped`로 탐지한다.
- 커널 ETW 세션 이름은 `logman query -ets`로 보인다. `trace_name`으로 바꿀 수 있다.
- x64 게스트만 지원한다. ETW 수집은 Windows 전용이다.
- `ts_ms`는 게스트 시계 기준이다. Cloud Logging 수신 시각(`recv_time`)을 기준으로 삼는다.
- 에이전트는 메모리 큐만 쓴다. 네트워크가 끊기면 큐가 차는 만큼 `dropped_queue`와 `dropped_send`가 늘고 해당 이벤트는 유실된다.
- UDP는 60초 중복 제거를 하고 ICMP는 수집하지 않는다. 이미 로드된 모듈은 수집하지 않는다.
- 일반 PC는 분석용 VM보다 이벤트가 훨씬 많다. 이미지 로드를 켠 양 측정(E8) 값은 참고용이며 VM에서 다시 측정한다.
- 전송, 종단 간 시험, 정리 스크립트는 아직 끝까지 실행해 검증하지 않았다(맨 위 검증 상태 참고).

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `src\` | 에이전트 소스 (Rust): `main.rs`, `config.rs`, `event.rs`, `etw.rs`, `sender.rs`, `gcp.rs`, `auth.rs`, `tls.rs` |
| `scripts\local-test\` | 원터치 테스트 러너 (`00_run.ps1`이 진입점, 나머지는 부품) |
| `scripts\harden.ps1` | 분석 VM 하드닝 |
| `gcp\setup.ps1`, `gcp\revoke-key.ps1` | GCP 구성과 키 관리 스크립트 |
| `gcp\functions\edr_monitor\` | 감시 Function 소스(`main.py`)와 단위 테스트(`test_main.py`) |
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
| `30_stage-gcp.ps1` | C, D 단계 (이 파일에 E 단계가 쓰는 공통 도구도 있다) |
| `40_stage-e2e.ps1` | E 단계 |
| `50_stage-cleanup.ps1` | F 단계 |

## 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 본다.
