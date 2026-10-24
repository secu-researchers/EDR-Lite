<#
================================================================================
 00_run.ps1 - EDR 일반 PC 테스트 원터치 실행기 (진입점)

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증). 처음 실행할 때 오류가 날 수 있습니다.

 이 스크립트가 하는 일
   체크리스트(EDR_일반PC_테스트_체크리스트.md)의 P~F 단계를 순서대로 자동 실행하고,
   항목별 판정(PASS / FAIL / SKIP / MANUAL)을 표로 보여 줍니다.
   필요한 값(프로젝트 ID, 웹훅 등)은 실행 중에 직접 물어봅니다.
   모든 명령의 출력과 요약은 %TEMP%\edr-test-<시각>\ 폴더에 저장됩니다.

 파일 구성 (같은 폴더)
   파일 이름 앞의 번호는 역할과 불러오는 순서를 뜻합니다.
   직접 실행하는 파일은 00 번 하나뿐이고, 나머지는 00 번이 불러다 쓰는 부품입니다.
   00_run.ps1           이 파일. 인자 처리, 단계 선택과 실행, 결과 요약. (유일하게 직접 실행)
   10_lib.ps1           공통 도구 (로그, 판정 기록, 외부 명령 실행, 에이전트 제어, GCP/BQ 도구).
   15_prompts.ps1       실행에 필요한 값을 묻는 부분 (Read-RunSettings).
   20_stage-local.ps1   P(준비), A(자동 테스트와 빌드), B(로컬 수집 확인)
   30_stage-gcp.ps1     C(GCP 구성), D(전송 확인)
   40_stage-e2e.ps1     E(종단 간 시험)
   50_stage-cleanup.ps1 F(정리)
   단계 파일이 없으면 해당 단계를 SKIP 으로 표시하고 건너뜁니다.

 사용법 (관리자 PowerShell, 저장소 루트 또는 이 폴더에서)
   # 인자 없이 실행: 범위(전체/로컬만)와 필요한 값을 차례로 묻습니다.
   .\scripts\local-test\00_run.ps1

   # 로컬 단계(P, A, B)만. GCP 에 접속하지 않고 아무 것도 묻지 않습니다.
   .\scripts\local-test\00_run.ps1 -LocalOnly

   # 특정 단계만
   .\scripts\local-test\00_run.ps1 -Stages A
   .\scripts\local-test\00_run.ps1 -Stages P,A,B

   # 값을 미리 주면 그 값은 다시 묻지 않습니다 (테스트 전용 프로젝트에서만!)
   .\scripts\local-test\00_run.ps1 -ProjectId <PROJECT_ID>

 실행 정책 때문에 막히면, 같은 창에서 먼저 한 번만 실행합니다 (창을 닫으면 원래대로 돌아감).
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

 안전 원칙
   - 악성코드를 실행하지 않습니다. 무해한 활동(cmd echo, curl, DNS 조회)만 만듭니다.
   - 스크립트가 시작한 프로세스만 PID 로 종료합니다. 이름으로 일괄 종료하지 않습니다.
   - GCP 를 바꾸는 단계 앞에서는 프로젝트 ID 를 직접 입력해 확인을 받습니다 (-Yes 로 생략 가능).
   - 키, 웹훅 주소, 토큰은 화면과 로그에 남기지 않습니다. 웹훅 주소는 SecureString 으로만 들고 있다가
     C 단계 동안 이 프로세스의 환경변수(EDR_WEBHOOK_URL)로 잠시 전달하고 바로 지웁니다.
   - GCP 를 건드린 실행은 중간에 멈추거나 실패해도 마지막에 F(정리)를 시도합니다.
   - 수집 파일(*.ndjson)에는 명령줄(cmdline)이 들어 있어 민감한 값이 섞일 수 있습니다.
     끝나면 -DeleteArtifacts 로 지우거나 직접 삭제하세요.

 인코딩 주의: 이 파일은 "UTF-8 (BOM 포함)" 으로 저장되어 있어야 합니다.
================================================================================
#>
[CmdletBinding()]
param(
    # GCP 프로젝트 ID. 비워 두면 GCP 단계가 필요할 때 물어본다.
    [string]$ProjectId = "",

    # GCP 리전 (비워 두면 GCP 단계가 필요할 때 물어본다. 기본 제안값 asia-northeast3)
    [string]$Region = "",

    # BigQuery 데이터 위치 (비워 두면 물어본다. 기본 제안값은 리전과 같은 값)
    [string]$BqLocation = "",

    # 실행할 단계. 주지 않으면 전체/로컬만 중에서 물어본다.
    [ValidateSet("P", "A", "B", "C", "D", "E", "F")]
    [string[]]$Stages,

    # 질문 없이 로컬 단계(P, A, B)만 실행한다. GCP 에 접속하지 않는다.
    [switch]$LocalOnly,

    # 세션 이름 접두사. 실제 세션 이름은 접두사 뒤에 월일시분이 붙는다 (예: run-test-10241530).
    # 세션 이름은 영문, 숫자, '-', '_' 만 쓸 수 있다.
    [string]$SessionPrefix = "run-test",

    # B 단계에서 에이전트를 돌려 두는 시간(초). heartbeat 가 10초 주기라 25초 미만은 25초로 올린다.
    [int]$DryRunSeconds = 40,

    # 서비스 계정 키를 저장할 경로 (저장소 밖이어야 함). 비우면 물어본다.
    [string]$KeyPath = "",

    # 에이전트 설정 파일(agent.toml) 경로. 비우면 물어본다.
    [string]$ConfigPath = "",

    # E8 에서 이미지 로드 수집을 켜고 측정하는 시간(분). 0 이면 물어본다.
    [int]$ImageLoadMinutes = 0,

    # 저장소 루트. 비우면 이 스크립트 위치(scripts\local-test)에서 두 단계 위로 잡는다.
    [string]$RepoRoot = "",

    # 한 단계에 FAIL 이 있어도 다음 단계를 계속 실행한다.
    [switch]$ContinueOnFail,

    # 최종 확인 질문 없이 진행한다 (GCP 를 바꾸므로 주의).
    [switch]$Yes,

    # 끝나면 수집 파일(*.ndjson)을 삭제한다. 로그와 요약은 남긴다.
    [switch]$DeleteArtifacts
)

# 오류가 나면 즉시 중단되도록 한다. (외부 명령의 stderr 는 10_lib.ps1 이 안전하게 처리한다.)
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# 1. 공통 도구와 단계 파일 불러오기
#    점 소싱(. 경로)은 파일 내용을 현재 범위에서 실행해, 함수와 $script: 변수를 공유하게 한다.
# ------------------------------------------------------------------------------
. (Join-Path $PSScriptRoot "10_lib.ps1")
. (Join-Path $PSScriptRoot "15_prompts.ps1")

# 단계 파일 목록. 파일이 있으면 불러온다 (없으면 해당 단계는 SKIP 처리된다).
$stageFiles = @(
    "20_stage-local.ps1",      # P, A, B
    "30_stage-gcp.ps1",        # C, D
    "40_stage-e2e.ps1",        # E
    "50_stage-cleanup.ps1"     # F
)
foreach ($f in $stageFiles) {
    $path = Join-Path $PSScriptRoot $f
    if (Test-Path -LiteralPath $path) { . $path }
}
# 단계 -> 실행할 함수 이름 대응표
$stageFunctions = [ordered]@{
    P = "Invoke-StageP"
    A = "Invoke-StageA"
    B = "Invoke-StageB"
    C = "Invoke-StageC"
    D = "Invoke-StageD"
    E = "Invoke-StageE"
    F = "Invoke-StageF"
}

# ------------------------------------------------------------------------------
# 2. 인자 정리와 값 묻기
# ------------------------------------------------------------------------------

# 저장소 루트 결정: 비어 있으면 scripts\local-test 에서 ..\.. 로 올라간다.
if ($RepoRoot -eq "") { $RepoRoot = Join-Path $PSScriptRoot "..\.." }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot "Cargo.toml"))) {
    throw ("저장소 루트가 아닙니다 (Cargo.toml 없음): " + $RepoRoot + " -RepoRoot 로 지정하세요.")
}

# 사용자가 -Stages 를 직접 줬을 때만 넘긴다 (안 줬으면 Read-RunSettings 가 범위를 묻는다).
$givenStages = @()
if ($PSBoundParameters.ContainsKey("Stages")) { $givenStages = @($Stages) }

# 필요한 값을 묻고 확정한다. 비밀 값(웹훅)은 SecureString 으로만 돌려받는다.
$settings = Read-RunSettings -Stages $givenStages -LocalOnly $LocalOnly.IsPresent `
    -ProjectId $ProjectId -Region $Region -BqLocation $BqLocation `
    -KeyPath $KeyPath -ConfigPath $ConfigPath -ImageLoadMinutes $ImageLoadMinutes `
    -RepoRoot $RepoRoot -AutoYes $Yes.IsPresent

if (-not $settings.Confirmed) {
    Write-Host "확인이 일치하지 않아 취소했습니다. 아무 것도 실행하지 않았습니다." -ForegroundColor Yellow
    exit 2
}

# 사용자가 순서를 바꿔 줘도 항상 P -> F 순서로 실행한다.
$order = @("P", "A", "B", "C", "D", "E", "F")
$selected = @($order | Where-Object { $settings.Stages -contains $_ })
if ($selected.Count -eq 0) { throw "실행할 단계가 없습니다." }

# 세션 이름 형식 확인 (에이전트 설정의 session_id 규칙: 영문, 숫자, '-', '_', 최대 64자)
$sessionName = $SessionPrefix + "-" + (Get-Date -Format "MMddHHmm")
if ($sessionName -notmatch '^[A-Za-z0-9_-]{1,64}$') {
    throw ("세션 이름 형식이 올바르지 않습니다: " + $sessionName)
}

# 20_stage-local.ps1 의 B 단계가 $script:DryRunSeconds 를 읽는다.
$script:DryRunSeconds = $DryRunSeconds

# ------------------------------------------------------------------------------
# 3. 실행
# ------------------------------------------------------------------------------
Initialize-TestRun -RepoRoot $RepoRoot -ProjectId $settings.ProjectId -Region $settings.Region `
    -SessionName $sessionName -Stages $selected -AutoYes $Yes.IsPresent

# 묻기로 확정한 값을 단계 파일들이 쓸 수 있게 공유 컨텍스트에 넣는다.
#   Webhook   SecureString 또는 $null (평문은 보관하지 않는다)
#   GcpTouched 이 실행이 GCP 를 바꾸기 시작했는지. true 이면 마지막에 F(정리)를 보장한다.
$script:Ctx.BqLocation       = $settings.BqLocation
$script:Ctx.KeyPath          = $settings.KeyPath
$script:Ctx.ConfigPath       = $settings.ConfigPath
$script:Ctx.ImageLoadMinutes = $settings.ImageLoadMinutes
$script:Ctx.Webhook          = $settings.Webhook
$script:Ctx.GcpTouched       = $false
$script:Ctx.FRan             = $false

Write-Host ""
Write-Host "================ EDR 일반 PC 테스트 ================" -ForegroundColor White
Write-Log ("저장소: " + $RepoRoot)
Write-Log ("실행 단계: " + ($selected -join ", "))
if ($settings.ProjectId -ne "") {
    Write-Log ("GCP 프로젝트: " + $settings.ProjectId + " / 리전: " + $settings.Region + " / BQ 위치: " + $settings.BqLocation)
    Write-Log ("웹훅: " + $(if ($null -ne $settings.Webhook) { "입력됨(표시하지 않음)" } else { "없음(알림 없이 진행)" }))
}
Write-Log ("로그 폴더: " + $script:Ctx.LogDir)

$failCount = 0
try {
    foreach ($s in $selected) {
        $fn = $stageFunctions[$s]

        # 단계 파일이 아직 없으면(다음 작업에서 작성 예정) SKIP 으로 기록하고 넘어간다.
        if (-not (Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue)) {
            Add-Result -Id $s -Title ($s + " 단계") -Status SKIP -Detail "이 단계의 스크립트 파일이 아직 없습니다."
            continue
        }

        Write-Host ""
        Write-Host ("---------------- " + $s + " 단계 ----------------") -ForegroundColor White

        # C 단계부터는 GCP 를 바꾼다. 이후 어디서 중단되든 마지막에 F 를 시도하도록 표시한다.
        if ("CDEF".Contains($s)) { $script:Ctx.GcpTouched = $true }
        if ($s -eq "F") { $script:Ctx.FRan = $true }

        $before = $script:Results.Count
        try {
            # C 단계(gcp\setup.ps1 호출)에서만 웹훅을 환경변수로 잠시 전달한다.
            # 자식 프로세스가 상속받아 읽고, 이 단계가 끝나면(성공이든 예외든) 바로 지운다.
            if ($s -eq "C" -and $null -ne $script:Ctx.Webhook) {
                $env:EDR_WEBHOOK_URL = ConvertFrom-SecureText -Secure $script:Ctx.Webhook
            }
            & $fn
        }
        catch {
            # 단계 함수 안에서 처리되지 않은 예외는 FAIL 로 기록하고 요약을 계속 진행한다.
            Add-Result -Id $s -Title ($s + " 단계 실행 중 예외") -Status FAIL -Detail $_.Exception.Message
        }
        finally {
            Remove-Item Env:\EDR_WEBHOOK_URL -ErrorAction SilentlyContinue
        }

        # 이 단계에서 새로 생긴 FAIL 이 있으면 다음 단계로 넘어가지 않는다 (체크리스트: 앞 단계가 통과해야 다음으로).
        $newResults = @($script:Results | Select-Object -Skip $before)
        $stageFails = @($newResults | Where-Object { $_.Status -eq "FAIL" }).Count
        if ($stageFails -gt 0 -and -not $ContinueOnFail) {
            Write-Log ($s + " 단계에 실패 항목이 있어 이후 단계를 건너뜁니다. (-ContinueOnFail 로 계속 가능)") "WARN"
            break
        }
    }
}
finally {
    # Ctrl+C 로 중단하거나 예외가 나도 반드시 정리한다:
    #   - 이 실행이 띄운 에이전트 프로세스 종료
    #   - 이 실행이 만든 ETW 커널 세션 삭제
    Stop-AllAgents

    # 웹훅 평문이 환경변수에 남지 않게 한다 (정상 경로에서는 이미 지워져 있다).
    Remove-Item Env:\EDR_WEBHOOK_URL -ErrorAction SilentlyContinue

    # GCP 를 바꿨는데 F(정리)가 실행되지 않았다면(앞 단계 실패, Ctrl+C 등) 여기서 정리를 시도한다.
    # 정리 내용: 서비스 계정 키 폐기, _Default 싱크 되돌리기 등 (50_stage-cleanup.ps1 이 정의).
    if ($script:Ctx.GcpTouched -and -not $script:Ctx.FRan) {
        if (Get-Command $stageFunctions["F"] -CommandType Function -ErrorAction SilentlyContinue) {
            Write-Log "GCP 를 변경한 실행이므로 F(정리)를 수행합니다." "WARN"
            $script:Ctx.FRan = $true
            try { & $stageFunctions["F"] }
            catch { Add-Result -Id "F" -Title "F 단계 실행 중 예외" -Status FAIL -Detail $_.Exception.Message }
        }
        else {
            Write-Log "GCP 를 변경했지만 F(정리) 스크립트가 없습니다. 서비스 계정 키(revoke-key.ps1)와 설정을 직접 정리하세요." "WARN"
        }
    }

    # 수집 파일에는 명령줄이 들어 있으므로 요청 시 삭제한다.
    if ($DeleteArtifacts) {
        Get-ChildItem -LiteralPath $script:Ctx.LogDir -Filter "*.ndjson" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "수집 파일(*.ndjson)을 삭제했습니다."
    }
    else {
        Write-Log "수집 파일(*.ndjson)에는 명령줄이 들어 있습니다. 필요 없으면 -DeleteArtifacts 또는 직접 삭제하세요." "WARN"
    }

    $failCount = Show-Summary
}

# 종료 코드: FAIL 이 하나라도 있으면 1, 없으면 0 (다른 스크립트에서 결과를 판정할 수 있게)
if ($failCount -gt 0) { exit 1 } else { exit 0 }
