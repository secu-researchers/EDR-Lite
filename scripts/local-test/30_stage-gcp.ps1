<#
================================================================================
 30_stage-gcp.ps1 - 체크리스트 C(GCP 구성), D(전송 확인) 단계

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증).

 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 점 소싱으로 불러오며 아래 함수를 호출합니다.

   Invoke-StageC   C1~C7  gcp\setup.ps1 로 GCP 리소스를 만들고 확인, 서비스 계정 키 발급
   Invoke-StageD   D1~D7  agent.toml 작성, --test 전송, BigQuery 도착 확인, 실패 시나리오

 GCP 를 실제로 바꿉니다 (리소스 생성, 로그 싱크 변경, 서비스 계정 키 발급).
 반드시 테스트 전용 프로젝트에서만 실행하세요. 최종 확인은 15_prompts.ps1 이 이미 받았습니다.

 이 단계가 $script:Ctx 에 남기는 값 (50_stage-cleanup.ps1 의 F 단계가 되돌릴 때 쓴다)
   DefaultSinkEnabled  C5 에서 _Default 로그 싱크를 켰는가
   KeyCreated, KeyId   C6 에서 이번 실행이 키를 새로 만들었는가, 그 키의 ID (비밀 아님)
   ConfigWritten       D1 에서 설정 파일(agent.toml)을 이번 실행이 만들었는가
   ConfigBackup        D1 에서 기존 설정 파일을 옮겨 둔 경로 (없으면 빈 문자열)
   D2Sid               D2 가 쓴 세션 이름 (D3 가 BigQuery 에서 찾는다)
   FirewallRules       D7 이 만든 방화벽 규칙 이름 목록 (정상이면 이미 지워져 있다)

 비밀 값 처리
   서비스 계정 키의 내용(private_key)은 읽거나 출력하지 않습니다. 식별용 정보(키 ID 등)만 봅니다.
   웹훅 주소는 setup.ps1 에 환경변수로만 전달되며(00_run.ps1 이 설정) 여기서는 다루지 않습니다.
================================================================================
#>


# ==============================================================================
# 공통 도구 (이 파일과 40_stage-e2e.ps1 이 함께 쓴다)
# ==============================================================================

<#
 Get-SessionId
   이번 실행의 세션 이름에 접미사를 붙여 단계마다 다른 세션 ID 를 만든다. 예: run-test-10241530-d2
   에이전트의 session_id 는 영문, 숫자, '-', '_' 만 되고 최대 64자이므로, 길면 앞부분을 자른다.
#>
function Get-SessionId {
    param([Parameter(Mandatory = $true)][string]$Suffix)
    $base = $script:Ctx.SessionName
    $maxBase = 64 - 1 - $Suffix.Length
    if ($base.Length -gt $maxBase) { $base = $base.Substring(0, $maxBase) }
    return ($base + "-" + $Suffix)
}

<#
 ConvertFrom-JsonItems
   JSON 텍스트를 객체 배열로 바꾼다. 비었거나 형식이 틀리면 빈 배열.
   gcloud, bq 의 --format=json 출력은 결과가 하나여도 배열이지만, ConvertFrom-Json 이 파이프라인에
   하나씩 풀어 내보내므로 호출하는 쪽에서 @( ) 로 감싸서 받는다.
#>
function ConvertFrom-JsonItems {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    try { $parsed = $Text | ConvertFrom-Json } catch { return @() }
    if ($null -eq $parsed) { return @() }
    return @($parsed)
}

<#
 Get-HeadText
   긴 출력에서 앞쪽 몇 줄만 한 줄로 합쳐 판정 설명(Detail)에 쓴다. 비밀 값이 든 출력에는 쓰지 않는다.
#>
function Get-HeadText {
    param([string]$Text, [int]$Lines = 3, [int]$MaxChars = 300)
    $parts = @($Text -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First $Lines)
    $joined = ($parts -join " / ").Trim()
    if ($joined.Length -gt $MaxChars) { $joined = $joined.Substring(0, $MaxChars) + "..." }
    return $joined
}

<#
 Invoke-AgentTest
   edr-lite.exe --config <파일> --test 를 실행하고 출력을 캡처한다 (Invoke-Captured 와 같은 반환 객체).
   --test 는 ETW 를 켜지 않고 agent_start, agent_stop 두 건만 Cloud Logging 으로 보낸 뒤 끝난다.
#>
function Invoke-AgentTest {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigFile,
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$TimeoutSec = 90
    )
    return Invoke-Captured -Name $Name -FilePath $script:Ctx.Exe `
        -ArgumentList @("--config", $ConfigFile, "--test") `
        -WorkingDirectory $script:Ctx.RepoRoot -TimeoutSec $TimeoutSec
}


# ==============================================================================
# C. GCP 구성
# ==============================================================================

function Invoke-StageC {
    $ctx = $script:Ctx
    $gcpDir = Join-Path $ctx.RepoRoot "gcp"
    $setupPs1 = Join-Path $gcpDir "setup.ps1"
    $revokePs1 = Join-Path $gcpDir "revoke-key.ps1"
    $schemaSql = Join-Path $gcpDir "schema.sql"
    $powershell = Resolve-Tool "powershell"
    $bq = Resolve-Tool "bq"
    $region = $ctx.Region
    $project = $ctx.ProjectId

    # ---- C1 스크립트 검토 ------------------------------------------------------
    # 사람이 읽어 검토하는 항목이지만, 자동으로는 파일이 있는지와 구문 오류가 없는지를 본다.
    $missing = @($setupPs1, $revokePs1, $schemaSql | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count -gt 0) {
        Add-Result -Id "C1" -Title "배포 스크립트 확인" -Status FAIL -Detail ("파일이 없습니다: " + ($missing -join ", "))
        return
    }
    $syntax = @()
    foreach ($p in @($setupPs1, $revokePs1)) {
        foreach ($e in (Test-ScriptSyntax -Path $p)) { $syntax += ((Split-Path -Leaf $p) + " " + $e) }
    }
    if ($syntax.Count -gt 0) {
        Add-Result -Id "C1" -Title "배포 스크립트 확인" -Status FAIL -Detail ("구문 오류: " + ($syntax -join "; "))
        return
    }
    Add-Result -Id "C1" -Title "배포 스크립트 확인" -Status PASS `
        -Detail "setup.ps1, revoke-key.ps1, schema.sql 존재, 구문 오류 없음 (내용 검토는 사람이 직접 하세요)"

    if (-not $powershell -or -not (Resolve-Tool "gcloud") -or -not $bq) {
        Add-Result -Id "C2" -Title "setup.ps1 실행" -Status FAIL -Detail "powershell, gcloud, bq 중 찾을 수 없는 도구가 있습니다."
        return
    }

    # ---- C2 setup.ps1 실행 -----------------------------------------------------
    # 새 PowerShell 프로세스에서 실행한다 (실행 정책 우회는 그 프로세스에만 적용).
    # 웹훅 주소는 00_run.ps1 이 환경변수 EDR_WEBHOOK_URL 로 설정해 두었고, 자식 프로세스가 상속한다.
    # 웹훅이 없으면 -SkipSecret 을 줘서 입력창(Read-Host)이 뜨며 멈추는 일을 막는다.
    $setupArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupPs1,
        "-ProjectId", $project, "-Region", $region, "-BqLocation", $ctx.BqLocation,
        "-HeartbeatSecs", "10"
    )
    if ($null -eq $ctx.Webhook) { $setupArgs += "-SkipSecret" }
    Write-Log "setup.ps1 실행 중... (Function 배포가 있어 10~20분 걸릴 수 있습니다)"
    $r = Invoke-Captured -Name "C2-setup" -FilePath $powershell -ArgumentList $setupArgs -TimeoutSec 2400
    if ($r.TimedOut) {
        Add-Result -Id "C2" -Title "setup.ps1 실행" -Status FAIL -Detail "제한 시간(40분)을 넘겨 중단했습니다. C2-setup.out.txt 확인"
        return
    }
    if ($r.ExitCode -eq 0 -and $r.Text -match "Done\. Remaining manual steps") {
        $note = ""
        if ($null -eq $ctx.Webhook) { $note = " (웹훅 없음: 경보가 Discord 로 가지 않습니다)" }
        Add-Result -Id "C2" -Title "setup.ps1 실행" -Status PASS -Detail ("7단계 완료" + $note)
    }
    else {
        Add-Result -Id "C2" -Title "setup.ps1 실행" -Status FAIL `
            -Detail ("종료 코드 " + $r.ExitCode + " | " + (Get-HeadText -Text $r.StdErr -Lines 3) + " (C2-setup.err.txt 확인)")
        return
    }

    # ---- C3 리소스 확인 --------------------------------------------------------
    $problems = @()

    $fnRun = Invoke-Gcloud -Name "C3-functions" -ArgumentList @("functions", "list", "--regions=$region", "--format=json")
    $fns = @(ConvertFrom-JsonItems $fnRun.StdOut)
    foreach ($fnName in @("edr-ingest", "edr-watchdog")) {
        $hit = @($fns | Where-Object { $_.name -match ("(^|/)" + [regex]::Escape($fnName) + "$") }) | Select-Object -First 1
        if (-not $hit) { $problems += ($fnName + " 없음") }
        elseif ($hit.state -ne "ACTIVE") { $problems += ($fnName + " 상태=" + $hit.state) }
    }

    $jobRun = Invoke-Gcloud -Name "C3-scheduler" -ArgumentList @("scheduler", "jobs", "list", "--location=$region", "--format=json")
    $jobs = @(ConvertFrom-JsonItems $jobRun.StdOut)
    $job = @($jobs | Where-Object { $_.name -match "(^|/)edr-watchdog-job$" }) | Select-Object -First 1
    if (-not $job) { $problems += "edr-watchdog-job 없음" }
    elseif ($job.state -ne "ENABLED") { $problems += ("edr-watchdog-job 상태=" + $job.state) }

    $sinkRun = Invoke-Gcloud -Name "C3-sinks" -ArgumentList @("logging", "sinks", "list", "--format=json")
    $sinks = @(ConvertFrom-JsonItems $sinkRun.StdOut)
    $mySink = @($sinks | Where-Object { $_.name -eq "edr-log-sink" }) | Select-Object -First 1
    if (-not $mySink) { $problems += "edr-log-sink 없음" }
    $defSink = @($sinks | Where-Object { $_.name -eq "_Default" }) | Select-Object -First 1
    if ($defSink -and -not ($defSink.disabled -eq $true)) { $problems += "_Default 싱크가 비활성이 아님" }

    if ($problems.Count -eq 0) {
        Add-Result -Id "C3" -Title "Function, Scheduler, 로그 싱크 확인" -Status PASS `
            -Detail "edr-ingest, edr-watchdog ACTIVE / edr-watchdog-job ENABLED / edr-log-sink 있음 / _Default 비활성"
    }
    else {
        Add-Result -Id "C3" -Title "Function, Scheduler, 로그 싱크 확인" -Status FAIL -Detail ($problems -join "; ")
    }

    # ---- C4 BigQuery 테이블 확인 -----------------------------------------------
    # events: recv_time 일 단위 파티션 + sid, kind 클러스터링 / alerts: 테이블이 존재
    $c4 = @()
    foreach ($t in @("events", "alerts")) {
        $spec = $project + ":edr_logs." + $t
        $show = Invoke-Captured -Name ("C4-bq-show-" + $t) -FilePath $bq `
            -ArgumentList @("show", "--format=prettyjson", ("--project_id=" + $project), $spec) -TimeoutSec 90
        if ($show.ExitCode -ne 0) { $c4 += ($t + " 테이블을 조회하지 못함"); continue }
        $meta = $show.StdOut | ConvertFrom-Json
        if ($t -eq "events") {
            if ($meta.timePartitioning.type -ne "DAY" -or $meta.timePartitioning.field -ne "recv_time") {
                $c4 += "events 가 recv_time 일 단위 파티션이 아님"
            }
            $clusterFields = ""
            if ($meta.clustering -and $meta.clustering.fields) { $clusterFields = ($meta.clustering.fields -join ",") }
            if ($clusterFields -ne "sid,kind") { $c4 += ("events 클러스터링이 sid,kind 가 아님(" + $clusterFields + ")") }
        }
    }
    if ($c4.Count -eq 0) {
        Add-Result -Id "C4" -Title "BigQuery 테이블 확인" -Status PASS -Detail "events(recv_time 일 파티션, sid/kind 클러스터), alerts 있음"
    }
    else {
        Add-Result -Id "C4" -Title "BigQuery 테이블 확인" -Status FAIL -Detail ($c4 -join "; ")
    }

    # ---- C5 시험 기간 동안 _Default 싱크 켜기 ------------------------------------
    # 켜 두면 에이전트 전송과 Function 오류를 로그로 추적할 수 있다. 저장분은 수집 요금 대상이라
    # F 단계(또는 00_run.ps1 의 마무리)가 다시 끈다.
    $on = Invoke-Gcloud -Name "C5-sink-on" -ArgumentList @("logging", "sinks", "update", "_Default", "--no-disabled")
    if ($on.ExitCode -eq 0) { $ctx.DefaultSinkEnabled = $true }
    $chk = Invoke-Gcloud -Name "C5-sink-check" -ArgumentList @("logging", "sinks", "list", "--format=json")
    $def2 = @(ConvertFrom-JsonItems $chk.StdOut | Where-Object { $_.name -eq "_Default" }) | Select-Object -First 1
    if ($on.ExitCode -eq 0 -and $def2 -and -not ($def2.disabled -eq $true)) {
        Add-Result -Id "C5" -Title "_Default 싱크 켜기(시험 기간 한정)" -Status PASS -Detail "활성화됨. F 단계에서 다시 끕니다."
    }
    else {
        Add-Result -Id "C5" -Title "_Default 싱크 켜기(시험 기간 한정)" -Status FAIL `
            -Detail ("종료 코드 " + $on.ExitCode + " | " + (Get-HeadText -Text $on.StdErr))
    }

    # ---- C6 서비스 계정 키 발급 --------------------------------------------------
    # 키는 저장소 밖 경로에만 둔다 (15_prompts.ps1 이 이미 확인). revoke-key.ps1 이 파일 접근을
    # 현재 사용자로 제한한다. 내용은 읽지 않고 식별 정보(키 ID, 계정, 프로젝트)만 확인한다.
    # 계정 이름은 검사하지 않는다 (type 과 project_id 만 확인). 쓰는 계정의 권한은 사람이 확인한다.
    $keyPath = $ctx.KeyPath
    $ctx.KeyCreated = $false
    $ctx.KeyId = ""
    if (Test-Path -LiteralPath $keyPath) {
        # 같은 경로에 이미 키가 있다: 이 프로젝트의 에이전트 계정 키라면 재사용하고, 아니면 멈춘다.
        $existing = Get-KeyInfo -Path $keyPath
        if ($existing -and $existing.Type -eq "service_account" -and $existing.ProjectId -eq $project) {
            Add-Result -Id "C6" -Title "서비스 계정 키 준비" -Status PASS `
                -Detail ("기존 키 파일을 재사용합니다(계정: " + $existing.ClientEmail + "). 이번 실행이 만든 키가 아니라 F 에서 폐기하지 않으니 끝나면 직접 정리하세요. 키 ID 끝 6자리: " + $existing.KeyId.Substring([math]::Max(0, $existing.KeyId.Length - 6)))
        }
        else {
            # 어느 항목이 달랐는지 밝힌다 (식별 정보만 사용하고 개인키는 읽거나 출력하지 않는다).
            $why = @()
            if (-not $existing) { $why += "JSON 으로 읽지 못함" }
            else {
                if ($existing.Type -ne "service_account") { $why += ("type=" + $existing.Type) }
                if ($existing.ProjectId -ne $project) { $why += ("project_id=" + $existing.ProjectId + " (기대: " + $project + ")") }
            }
            Add-Result -Id "C6" -Title "서비스 계정 키 준비" -Status FAIL `
                -Detail ("경로의 기존 파일을 서비스 계정 키로 쓸 수 없습니다: " + $keyPath + " | 다른 항목: " + ($why -join "; ") +
                         " | 파일 이름을 바꾸거나 다른 경로를 지정하세요.")
            return
        }
    }
    else {
        $dir = Split-Path -Parent $keyPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $kr = Invoke-Captured -Name "C6-key-new" -FilePath $powershell -TimeoutSec 180 -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $revokePs1,
            "-ProjectId", $project, "-Action", "New", "-OutFile", $keyPath)
        $info = $null
        if ($kr.ExitCode -eq 0) { $info = Get-KeyInfo -Path $keyPath }
        if ($info -and $info.Type -eq "service_account") {
            $ctx.KeyCreated = $true
            $ctx.KeyId = $info.KeyId
            Add-Result -Id "C6" -Title "서비스 계정 키 준비" -Status PASS `
                -Detail ("키 발급됨(내용은 표시하지 않음). 키 ID 끝 6자리: " + $info.KeyId.Substring([math]::Max(0, $info.KeyId.Length - 6)))
        }
        else {
            Add-Result -Id "C6" -Title "서비스 계정 키 준비" -Status FAIL `
                -Detail ("종료 코드 " + $kr.ExitCode + " | " + (Get-HeadText -Text $kr.StdErr) + " (C6-key-new.err.txt 확인)")
            return
        }
    }

    # ---- C7 월 예산 알림 ------------------------------------------------------------
    # 예산은 콘솔에서 사람이 만든다. 예산 알림은 경고만 하고 지출을 막지 않는다.
    Add-Result -Id "C7" -Title "월 예산 알림 생성" -Status MANUAL `
        -Detail "콘솔 Billing > Budgets & alerts 에서 월 5,000원 안팎, 50%와 100% 알림을 만드세요."
}


# ==============================================================================
# D. 전송 확인 (--test)
# ==============================================================================

function Invoke-StageD {
    $ctx = $script:Ctx
    $exe = $ctx.Exe
    $project = $ctx.ProjectId
    $region = $ctx.Region
    $cfgPath = $ctx.ConfigPath
    $keyPath = $ctx.KeyPath

    # 사전 조건: 실행 파일(A3 빌드)과 키 파일(C6)
    if (-not (Test-Path -LiteralPath $exe)) {
        Add-Result -Id "D1" -Title "agent.toml 작성" -Status FAIL -Detail ("실행 파일이 없습니다: " + $exe + " (A3 빌드 먼저)")
        return
    }
    if (-not (Test-Path -LiteralPath $keyPath)) {
        Add-Result -Id "D1" -Title "agent.toml 작성" -Status FAIL -Detail ("키 파일이 없습니다: " + $keyPath + " (C6 먼저)")
        return
    }

    # ---- D1 agent.toml 작성 -----------------------------------------------------
    # 같은 경로에 이전 설정이 있으면 지우지 않고 .bak-<시각> 로 옮겨 둔다 (F 에서 되돌린다).
    $sidD2 = Get-SessionId "d2"
    $ctx.D2Sid = $sidD2
    $ctx.ConfigBackup = ""
    if (Test-Path -LiteralPath $cfgPath) {
        $backup = $cfgPath + ".bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        Move-Item -LiteralPath $cfgPath -Destination $backup
        $ctx.ConfigBackup = $backup
        Write-Log ("기존 설정 파일을 옮겼습니다: " + $backup) "WARN"
    }
    $text = New-AgentConfigText -ProjectId $project -KeyPath $keyPath -SessionId $sidD2 -ImageLoads $false -HeartbeatSecs 10
    Write-TextFile -Path $cfgPath -Text $text
    $ctx.ConfigWritten = $true
    Add-Result -Id "D1" -Title "agent.toml 작성" -Status PASS `
        -Detail ("작성함: " + $cfgPath + " (키 이름이 틀리면 D2 에서 '알 수 없는 필드' 오류가 납니다)")

    # ---- D2 정상 전송 시험 --------------------------------------------------------
    Write-Log "D2: edr-lite --test 실행"
    $r = Invoke-AgentTest -ConfigFile $cfgPath -Name "D2-test"
    if ($r.ExitCode -eq 0 -and $r.Text -match "연결 테스트 성공: 이벤트 2건 전송") {
        Add-Result -Id "D2" -Title "정상 전송 시험(--test)" -Status PASS -Detail ("세션 " + $sidD2 + ": 이벤트 2건 전송")
    }
    else {
        Add-Result -Id "D2" -Title "정상 전송 시험(--test)" -Status FAIL `
            -Detail ("종료 코드 " + $r.ExitCode + " | " + (Get-HeadText -Text $r.StdErr -Lines 4) +
                     " (토큰 발급 실패=키나 시계 문제, HTTP 403/404=권한이나 프로젝트 ID 문제)")
        return   # 전송이 안 되면 D3 는 의미가 없다
    }

    # ---- D3 수집 경로 확인 --------------------------------------------------------
    # Cloud Logging -> 싱크 -> Pub/Sub -> edr-ingest -> events. 지연이 있어 최대 5분까지 15초 간격으로 다시 본다.
    $sql = "SELECT kind, COUNT(*) AS n FROM " + (Get-BqTable "events") +
           " WHERE sid = '" + $sidD2 + "' AND recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR) GROUP BY kind"
    Write-Log "D3: BigQuery 에 도착할 때까지 확인 중 (최대 5분)"
    $rows = Wait-BqRows -Name "D3-events" -Sql $sql -TimeoutSec 300 -IntervalSec 15 -Condition {
        param($rs)
        (@($rs | Where-Object { $_.kind -eq "agent_start" }).Count -ge 1) -and
        (@($rs | Where-Object { $_.kind -eq "agent_stop" }).Count -ge 1)
    }
    if ($null -ne $rows) {
        Add-Result -Id "D3" -Title "BigQuery 도착 확인" -Status PASS -Detail ("sid=" + $sidD2 + " 의 agent_start, agent_stop 도착")
    }
    else {
        # 구간을 나눠 볼 수 있도록 Function 로그를 로그 폴더에 남긴다 (C5 에서 _Default 를 켰기 때문에 볼 수 있다).
        [void](Invoke-Gcloud -Name "D3-ingest-logs" -ArgumentList @("functions", "logs", "read", "edr-ingest", "--gen2", "--region=$region", "--limit=50"))
        Add-Result -Id "D3" -Title "BigQuery 도착 확인" -Status FAIL `
            -Detail "5분 안에 도착하지 않았습니다. D3-ingest-logs.out.txt 에 Function 로그를 저장했습니다. 콘솔 Logs Explorer 에서 로그 이름 lab_malware 항목도 확인하세요."
    }

    # ---- D4 Pub/Sub 디버그 구독 ----------------------------------------------------
    # 구간 진단용 선택 항목이라 자동으로 만들지 않는다 (만들면 F 에서 지워야 하는 리소스가 늘어난다).
    Add-Result -Id "D4" -Title "Pub/Sub 디버그 구독(선택)" -Status SKIP `
        -Detail "D3 가 실패했을 때만 체크리스트 D4 의 명령으로 직접 확인하세요."

    # ---- D5 실패 시나리오: 존재하지 않는 프로젝트 ID ---------------------------------
    # 형식은 맞지만 없는 프로젝트로 보낸다. 재시도 3번 뒤 포기하고 종료 코드 1 이어야 한다.
    $badProject = "edr-nonexist-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    $d5Cfg = Join-Path $ctx.LogDir "d5-agent.toml"
    Write-TextFile -Path $d5Cfg -Text (New-AgentConfigText -ProjectId $badProject -KeyPath $keyPath -SessionId (Get-SessionId "d5"))
    $r5 = Invoke-AgentTest -ConfigFile $d5Cfg -Name "D5-badproject"
    if ($r5.ExitCode -eq 1 -and $r5.Text -match "송신 실패 \(3/3\)" -and $r5.Text -match "치명적 오류") {
        Add-Result -Id "D5" -Title "실패 시나리오: 잘못된 프로젝트 ID" -Status PASS -Detail "재시도 3번 뒤 종료 코드 1로 끝남"
    }
    else {
        Add-Result -Id "D5" -Title "실패 시나리오: 잘못된 프로젝트 ID" -Status FAIL `
            -Detail ("종료 코드 " + $r5.ExitCode + ", 시간 초과=" + $r5.TimedOut + " | " + (Get-HeadText -Text $r5.StdErr -Lines 4))
    }

    # ---- D6 실패 시나리오: 키 파일 오류 ----------------------------------------------
    # (a) 없는 경로 (b) JSON 이 아닌 파일. 둘 다 전송 시도 전에 즉시 실패해야 한다.
    $missingKey = Join-Path $ctx.LogDir "no-such-key.json"
    $notJson = Join-Path $ctx.LogDir "not-a-key.json"
    Write-TextFile -Path $notJson -Text "this is not json"
    $d6Problems = @()
    $d6Cases = @(
        @{ Name = "missing"; Key = $missingKey },
        @{ Name = "notjson"; Key = $notJson }
    )
    foreach ($case in $d6Cases) {
        $cfg6 = Join-Path $ctx.LogDir ("d6-" + $case.Name + ".toml")
        Write-TextFile -Path $cfg6 -Text (New-AgentConfigText -ProjectId $project -KeyPath $case.Key -SessionId (Get-SessionId ("d6" + $case.Name.Substring(0, 1))))
        $r6 = Invoke-AgentTest -ConfigFile $cfg6 -Name ("D6-" + $case.Name) -TimeoutSec 30
        $okMsg = ($r6.Text -match "서비스 계정 키를 읽을 수 없음" -or $r6.Text -match "서비스 계정 키 JSON 형식 오류")
        if ($r6.ExitCode -eq 0 -or -not $okMsg -or $r6.Text -match "연결 테스트 성공") {
            $d6Problems += ($case.Name + ": 종료 코드 " + $r6.ExitCode + " | " + (Get-HeadText -Text $r6.StdErr -Lines 2))
        }
    }
    if ($d6Problems.Count -eq 0) {
        Add-Result -Id "D6" -Title "실패 시나리오: 키 파일 오류" -Status PASS -Detail "없는 경로, JSON 아님 모두 즉시 오류로 종료"
    }
    else {
        Add-Result -Id "D6" -Title "실패 시나리오: 키 파일 오류" -Status FAIL -Detail ($d6Problems -join "; ")
    }

    # ---- D7 실패 시나리오: 네트워크 단절 ----------------------------------------------
    # 체크리스트는 네트워크 어댑터를 끄지만, 자동 실행에서는 VPN 과 다른 작업을 끊을 수 있어
    # 에이전트 실행 파일만 막는 아웃바운드 방화벽 규칙으로 대신한다 (에이전트 입장에서는 같은 증상).
    if (-not (Test-IsAdmin)) {
        Add-Result -Id "D7" -Title "실패 시나리오: 네트워크 단절" -Status SKIP -Detail "방화벽 규칙을 만들려면 관리자 권한이 필요합니다."
    }
    else {
        $ruleName = "edr-test-block"
        $d7Problems = @()
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $exe -Action Block | Out-Null
            if (-not $ctx.FirewallRules) { $ctx.FirewallRules = @() }
            $ctx.FirewallRules += $ruleName

            $r7 = Invoke-AgentTest -ConfigFile $cfgPath -Name "D7-blocked" -TimeoutSec 90
            if ($r7.ExitCode -eq 0 -or $r7.Text -notmatch "토큰 요청 오류") {
                $d7Problems += ("차단 중 실행: 종료 코드 " + $r7.ExitCode + " | " + (Get-HeadText -Text $r7.StdErr -Lines 2))
            }
        }
        finally {
            # 성공이든 예외든 규칙을 반드시 지운다.
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            $ctx.FirewallRules = @($ctx.FirewallRules | Where-Object { $_ -ne $ruleName })
        }

        # 복구 확인: 규칙을 지운 뒤 같은 설정으로 D2 와 같은 시험이 다시 성공해야 한다.
        $r7b = Invoke-AgentTest -ConfigFile $cfgPath -Name "D7-recovered"
        if ($r7b.ExitCode -ne 0 -or $r7b.Text -notmatch "연결 테스트 성공") {
            $d7Problems += ("차단 해제 후 재시도 실패: 종료 코드 " + $r7b.ExitCode)
        }
        if ($d7Problems.Count -eq 0) {
            Add-Result -Id "D7" -Title "실패 시나리오: 네트워크 단절" -Status PASS -Detail "차단 중 토큰 요청 오류로 종료, 해제 후 전송 성공"
        }
        else {
            Add-Result -Id "D7" -Title "실패 시나리오: 네트워크 단절" -Status FAIL -Detail ($d7Problems -join "; ")
        }
    }
}
