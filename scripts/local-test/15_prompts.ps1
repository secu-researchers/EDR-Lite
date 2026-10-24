<#
================================================================================
 15_prompts.ps1 - 실행에 필요한 값을 사용자에게 물어보는 부분

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증).

 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 점 소싱으로 불러와 Read-RunSettings 를 호출합니다.
 10_lib.ps1 의 도구(Read-WithDefault, Read-SecretSecure, ConvertFrom-SecureText)를 씁니다.

 무엇을 묻는가 (이미 인자로 받은 값은 다시 묻지 않습니다)
   1. 실행 범위       전체(P~F) 또는 로컬만(P, A, B)
   2. 프로젝트 ID     GCP 테스트 전용 프로젝트 (필수)
   3. 리전, BigQuery 위치
   4. Discord 웹훅    입력이 화면에 표시되지 않음. 비워 두면 알림 없이 진행
   5. 키 파일, 설정 파일 경로
   6. 이미지 로드 측정 시간(분)
   7. 최종 확인       비용과 개인정보 경고를 보여 준 뒤 프로젝트 ID 를 그대로 입력해야 진행

 비밀 값 처리
   웹훅 주소는 SecureString 으로만 보관하며 화면, 로그, 명령줄 인자에 남기지 않습니다.
   (이후 setup.ps1 실행 때만 자식 프로세스의 환경변수로 잠시 전달하고 바로 지웁니다.)
================================================================================
#>

<#
 Read-RunSettings
   값을 묻고 확정한 설정을 객체로 돌려준다. 반환 객체의 필드:
     Stages            실행할 단계 배열
     ProjectId, Region, BqLocation, KeyPath, ConfigPath, ImageLoadMinutes
     Webhook           SecureString 또는 $null (알림 없이 진행)
     Confirmed         사용자가 최종 확인을 했는지 ($false 이면 실행하지 않는다)

   인자
     Stages            인자로 받은 단계 (비어 있으면 범위를 묻는다)
     LocalOnly         $true 이면 질문 없이 로컬 단계만 쓴다
     나머지            이미 값이 있으면 묻지 않는다
#>
function Read-RunSettings {
    param(
        [string[]]$Stages = @(),
        [bool]$LocalOnly = $false,
        [string]$ProjectId = "",
        [string]$Region = "",
        [string]$BqLocation = "",
        [string]$KeyPath = "",
        [string]$ConfigPath = "",
        [int]$ImageLoadMinutes = 0,
        [string]$RepoRoot = "",
        [bool]$AutoYes = $false
    )

    $localStages = @("P", "A", "B")
    $allStages   = @("P", "A", "B", "C", "D", "E", "F")

    # ---- 1. 실행 범위 --------------------------------------------------------
    if ($LocalOnly) {
        $Stages = $localStages
    }
    elseif (-not $Stages -or $Stages.Count -eq 0) {
        # 사용자가 아무 것도 지정하지 않았으면 범위를 묻는다. 대화형 콘솔이 아니면 물을 수 없다.
        if (-not [Environment]::UserInteractive) {
            throw "대화형 콘솔이 아니라 값을 물어볼 수 없습니다. -LocalOnly 또는 -Stages 와 필요한 인자를 지정하세요."
        }
        Write-Host ""
        Write-Host "실행 범위를 고르세요." -ForegroundColor White
        Write-Host "  1) 전체 실행 (P~F: 로컬 검증, GCP 구성, 전송 확인, 종단 간 시험, 정리)"
        Write-Host "  2) 로컬만 실행 (P, A, B: GCP 에 접속하지 않음)"
        $choice = Read-WithDefault -Prompt "번호" -Default "1"
        if ($choice -eq "2") { $Stages = $localStages } else { $Stages = $allStages }
    }

    # GCP 가 필요한 단계(C~F)가 하나도 없으면 더 물을 것이 없다.
    $needGcp = (@($Stages | Where-Object { "CDEF".Contains($_) }).Count -gt 0)
    if (-not $needGcp) {
        return [pscustomobject]@{
            Stages = $Stages; ProjectId = $ProjectId; Region = $Region; BqLocation = $BqLocation
            KeyPath = $KeyPath; ConfigPath = $ConfigPath; ImageLoadMinutes = $ImageLoadMinutes
            Webhook = $null; Confirmed = $true
        }
    }

    if (-not [Environment]::UserInteractive) {
        throw "대화형 콘솔이 아니라 값을 물어볼 수 없습니다."
    }

    Write-Host ""
    Write-Host "================ GCP 단계 실행 전 안내 ================" -ForegroundColor Yellow
    Write-Host "  - 테스트 전용 GCP 프로젝트에서만 실행하세요 (다른 용도의 프로젝트 금지)."
    Write-Host "  - 이 PC 의 프로세스 이벤트가 GCP 로 업로드됩니다. 명령줄(cmdline)에 경로, 사용자 이름,"
    Write-Host "    인자에 든 토큰이 섞일 수 있으므로 민감한 작업은 닫고 진행하세요."
    Write-Host "  - 전체 실행에는 대략 20~40분이 걸리고 소액의 GCP 비용이 발생할 수 있습니다."
    Write-Host "  - 끝에 서비스 계정 키 폐기와 설정 되돌리기를 수행합니다. 프로젝트나 데이터 삭제는"
    Write-Host "    별도로 확인을 받고, 기본값은 삭제하지 않음입니다."
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host ""

    # ---- 2. 프로젝트 ID ------------------------------------------------------
    # GCP 프로젝트 ID 규칙: 6~30자, 소문자로 시작, 소문자/숫자/하이픈, 하이픈으로 끝나지 않음.
    $idPattern = '^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
    $tries = 0
    while ($ProjectId -notmatch $idPattern) {
        if ($tries -ge 5) { throw "프로젝트 ID 입력이 5번 올바르지 않아 중단합니다." }
        if ($ProjectId -ne "") {
            Write-Host "형식이 올바르지 않습니다 (6~30자, 소문자로 시작, 소문자/숫자/하이픈, 하이픈으로 끝날 수 없음)." -ForegroundColor Yellow
        }
        $ProjectId = Read-WithDefault -Prompt "GCP 테스트 전용 프로젝트 ID" -Default ""
        $tries++
    }

    # ---- 3. 리전과 BigQuery 위치 ----------------------------------------------
    if ($Region -eq "") { $Region = Read-WithDefault -Prompt "Function 과 Scheduler 를 만들 리전" -Default "asia-northeast3" }
    if ($BqLocation -eq "") { $BqLocation = Read-WithDefault -Prompt "BigQuery 데이터 위치" -Default $Region }

    # ---- 4. Discord 웹훅 ------------------------------------------------------
    # 환경변수에 이미 있으면 그 값을 쓰고, 없으면 숨김 입력으로 받는다. 비우면 알림 없이 진행한다.
    $webhook = $null
    if ($env:EDR_WEBHOOK_URL) {
        Write-Host "환경변수 EDR_WEBHOOK_URL 의 값을 웹훅으로 사용합니다." -ForegroundColor Gray
        $webhook = ConvertTo-SecureString -String $env:EDR_WEBHOOK_URL -AsPlainText -Force
    }
    else {
        for ($i = 0; $i -lt 3; $i++) {
            $webhook = Read-SecretSecure -Prompt "Discord 웹훅 주소 (입력이 표시되지 않음, 비워 두면 알림 없이 진행)"
            if ($null -eq $webhook) { break }
            # 형식만 확인한다. 평문은 확인 직후 지운다.
            $plain = ConvertFrom-SecureText -Secure $webhook
            $looksOk = ($plain -match '^https://(discord|discordapp)\.com/api/webhooks/')
            $plain = $null
            if ($looksOk) { break }
            Write-Host "Discord 웹훅 주소 형식(https://discord.com/api/webhooks/...)이 아닙니다. 다시 입력하거나 비워 두세요." -ForegroundColor Yellow
            $webhook = $null
        }
    }

    # ---- 5. 파일 경로 ----------------------------------------------------------
    # 서비스 계정 키는 저장소 안에 두면 git 에 올라갈 수 있으므로 저장소 밖만 허용한다.
    $repoFull = ""
    if ($RepoRoot -ne "") { $repoFull = [System.IO.Path]::GetFullPath($RepoRoot) }
    $tries = 0
    while ($true) {
        if ($KeyPath -eq "") { $KeyPath = Read-WithDefault -Prompt "서비스 계정 키를 저장할 경로 (저장소 밖)" -Default "C:\edr\sa-key.json" }
        $keyFull = [System.IO.Path]::GetFullPath($KeyPath)
        $inside = ($repoFull -ne "" -and $keyFull.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase))
        if (-not $inside) { $KeyPath = $keyFull; break }
        Write-Host "키 파일은 저장소 안에 둘 수 없습니다: $keyFull" -ForegroundColor Yellow
        $KeyPath = ""
        $tries++
        if ($tries -ge 3) { throw "키 파일 경로가 3번 올바르지 않아 중단합니다." }
    }
    if ($ConfigPath -eq "") { $ConfigPath = Read-WithDefault -Prompt "에이전트 설정 파일(agent.toml) 경로" -Default "C:\edr\agent.toml" }
    $ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)

    # ---- 6. 이미지 로드 측정 시간 ------------------------------------------------
    # E8 에서 이미지 로드 수집을 켜고 측정하는 시간. 길수록 이벤트와 비용이 늘어난다 (1~30분).
    if ($ImageLoadMinutes -lt 1) {
        $text = Read-WithDefault -Prompt "이미지 로드 측정 시간(분, 1~30)" -Default "3"
        $ImageLoadMinutes = 3
        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) { $ImageLoadMinutes = $parsed }
    }
    if ($ImageLoadMinutes -lt 1) { $ImageLoadMinutes = 1 }
    if ($ImageLoadMinutes -gt 30) { $ImageLoadMinutes = 30 }

    # ---- 7. 최종 확인 ------------------------------------------------------------
    Write-Host ""
    Write-Host "---------------- 실행 설정 확인 ----------------" -ForegroundColor White
    Write-Host ("  실행 단계        : " + ($Stages -join ", "))
    Write-Host ("  GCP 프로젝트     : " + $ProjectId)
    Write-Host ("  리전 / BQ 위치   : " + $Region + " / " + $BqLocation)
    $hook = "없음 (알림 없이 진행)"
    if ($null -ne $webhook) { $hook = "입력됨 (표시하지 않음)" }
    Write-Host ("  Discord 웹훅     : " + $hook)
    Write-Host ("  키 파일          : " + $KeyPath)
    Write-Host ("  설정 파일        : " + $ConfigPath)
    Write-Host ("  이미지 로드 측정 : " + $ImageLoadMinutes + "분")
    Write-Host "------------------------------------------------" -ForegroundColor White

    $confirmed = $true
    if (-not $AutoYes) {
        $typed = Read-Host "위 내용으로 진행하려면 프로젝트 ID 를 정확히 입력하세요 (그 외 입력은 취소)"
        $confirmed = ($typed.Trim() -eq $ProjectId)
    }

    return [pscustomobject]@{
        Stages = $Stages; ProjectId = $ProjectId; Region = $Region; BqLocation = $BqLocation
        KeyPath = $KeyPath; ConfigPath = $ConfigPath; ImageLoadMinutes = $ImageLoadMinutes
        Webhook = $webhook; Confirmed = $confirmed
    }
}
