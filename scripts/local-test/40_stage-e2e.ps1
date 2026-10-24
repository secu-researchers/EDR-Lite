<#
================================================================================
 40_stage-e2e.ps1 - 체크리스트 E(종단 간 시험) 단계

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증).

 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 점 소싱으로 불러오며 Invoke-StageE 를 호출합니다.
 30_stage-gcp.ps1 의 Get-SessionId, ConvertFrom-JsonItems, Get-HeadText 를 함께 씁니다.

 실제 수집(ETW)을 켠 에이전트가 GCP 로 보내고, Function 과 BigQuery 가 처리한 결과를 확인합니다.
 대략 25~35분이 걸립니다 (경보 지연, 중복 방지 확인, 이미지 로드 측정 시간 포함).

   E1  수집 경로          에이전트 -> Cloud Logging -> 싱크 -> Pub/Sub -> edr-ingest -> events
   E2  ETW 중지 경보      logman 으로 세션을 중지 -> etw_stopped 경보
   E7  경보 중복 방지      E2 를 30분 안에 한 번 더 -> 이벤트는 쌓이지만 경보는 1건
   E3  heartbeat 공백     에이전트 강제 종료 -> watchdog 의 heartbeat_silence 경보
   E4  정상 종료는 경보 없음
   E5  전송 중단과 복구    에이전트 실행 파일만 막는 방화벽 규칙 -> 복구 뒤 seq_gap 경보가 오지 않아야 함
   E6  위조 로그는 거부    잘못된 kind 의 로그 -> invalid_event 경보, events 에 적재되지 않음
   E8  이미지 로드 양 측정  비용 추정용 수치 기록

 실행 순서는 E1, E2, E7, E3, E4, E5, E6, E8 입니다 (E7 이 E2 의 직후에 와야 하고,
 E3 은 E1~E7 이 쓴 에이전트를 강제 종료하기 때문).

 경보 도착은 BigQuery 의 alerts 테이블 행으로 자동 확인합니다 (웹훅이 없어도 이력은 남습니다).
 Discord 에 실제로 왔는지는 스크립트가 볼 수 없어, 웹훅을 입력한 경우에만 사람에게 묻습니다.

 안전 원칙
   - 에이전트는 이 스크립트가 PID 로 시작하고 PID 로만 종료합니다.
   - 방화벽 규칙은 에이전트 실행 파일 하나만 막고, 끝나면 반드시 지웁니다 (예외가 나도 finally).
   - 위조 로그 전송에 쓰는 접근 토큰은 변수에만 두고 파일, 화면, 로그에 남기지 않습니다.
================================================================================
#>


# ==============================================================================
# 도구
# ==============================================================================

<#
 ConvertTo-KindMap
   "SELECT kind, COUNT(*) AS n ... GROUP BY kind" 결과 행을 해시테이블(종류 -> 개수)로 바꾼다.
#>
function ConvertTo-KindMap {
    param($Rows)
    $map = @{}
    foreach ($r in @($Rows)) {
        if ($null -ne $r -and $r.kind) { $map[[string]$r.kind] = [int]$r.n }
    }
    return $map
}

<#
 Wait-KindMap
   세션의 이벤트 종류별 개수가 조건을 만족할 때까지 BigQuery 를 다시 조회한다.
   Test 는 해시테이블(종류 -> 개수)을 받아 $true/$false 를 돌려주는 스크립트블록이다.
   반환: 조건을 만족한 시점의 해시테이블. 시간 안에 만족하지 못하면 $null (마지막 조회 값은 $script:LastKindMap).
#>
function Wait-KindMap {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][scriptblock]$Test,
        [int]$TimeoutSec = 240
    )
    $sql = "SELECT kind, COUNT(*) AS n FROM " + (Get-BqTable "events") +
           " WHERE sid = '" + $Sid + "' AND recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR) GROUP BY kind"
    # GetNewClosure 는 쓰지 않는다: 닫힌 스크립트블록은 이 파일의 함수와 $script: 변수를 보지 못한다.
    # 대신 PowerShell 의 동적 범위로 $Test 를 본다 (10_lib.ps1 의 Wait-Until 과 같은 방식).
    $cond = { param($rs) $m = ConvertTo-KindMap $rs; $script:LastKindMap = $m; [bool](& $Test $m) }
    $script:LastKindMap = @{}
    $rows = Wait-BqRows -Name ("kinds-" + $Sid) -Sql $sql -Condition $cond -TimeoutSec $TimeoutSec -IntervalSec 15
    if ($null -eq $rows) { return $null }
    return (ConvertTo-KindMap $rows)
}

<#
 Get-AlertCount
   alerts 테이블에서 (세션, 사유) 경보 이력 개수를 센다 (최근 3시간).
#>
function Get-AlertCount {
    param([Parameter(Mandatory = $true)][string]$Sid, [Parameter(Mandatory = $true)][string]$Reason)
    $sql = "SELECT COUNT(*) AS n FROM " + (Get-BqTable "alerts") +
           " WHERE sid = '" + $Sid + "' AND reason = '" + $Reason +
           "' AND alert_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)"
    $rows = @(Invoke-BqQuery -Name ("alerts-" + $Reason) -Sql $sql)
    if ($rows.Count -eq 0) { return 0 }
    return [int]$rows[0].n
}

<#
 Wait-AlertCount
   (세션, 사유) 경보 이력이 Min 건 이상이 될 때까지 기다린다. 시간 안에 되면 $true.
#>
function Wait-AlertCount {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$Reason,
        [int]$Min = 1,
        [int]$TimeoutSec = 240
    )
    $sql = "SELECT COUNT(*) AS n FROM " + (Get-BqTable "alerts") +
           " WHERE sid = '" + $Sid + "' AND reason = '" + $Reason +
           "' AND alert_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)"
    $cond = { param($rs) (@($rs).Count -gt 0) -and ([int]@($rs)[0].n -ge $Min) }   # $Min 은 동적 범위로 읽는다
    $rows = Wait-BqRows -Name ("wait-alert-" + $Reason) -Sql $sql -Condition $cond -TimeoutSec $TimeoutSec -IntervalSec 15
    return ($null -ne $rows)
}

<#
 Start-EdrSession
   실제 수집 모드(ETW 켬)로 에이전트를 시작한다. 시험마다 별도의 설정 파일(로그 폴더)과 세션 ID 를 쓰므로
   D1 에서 만든 agent.toml 은 건드리지 않는다.
   반환: Agent(프로세스 정보), Ready(TraceName, AgentPid), Sid. 시작하지 못하면 $null.
#>
function Start-EdrSession {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$Tag,
        [bool]$ImageLoads = $false
    )
    $ctx = $script:Ctx
    $cfg = Join-Path $ctx.LogDir ("e-" + $Tag + ".toml")
    Write-TextFile -Path $cfg -Text (New-AgentConfigText -ProjectId $ctx.ProjectId -KeyPath $ctx.KeyPath -SessionId $Sid -ImageLoads $ImageLoads -HeartbeatSecs 10)
    $agent = Start-EdrAgent -Exe $ctx.Exe -AgentArgs ('--config "' + $cfg + '"') -Tag ("E-" + $Tag)
    $ready = Wait-AgentReady -Agent $agent -TimeoutSec 40
    if (-not $ready) {
        Write-Log ("에이전트 시작 실패(" + $Tag + "): " + (Get-HeadText -Text ((Read-SharedLines -Path $agent.ErrFile) -join "`n") -Lines 4)) "ERROR"
        [void](Stop-EdrAgent -Agent $agent -Force)
        return $null
    }
    return [pscustomobject]@{ Agent = $agent; Ready = $ready; Sid = $Sid }
}

<#
 Stop-EtwSession
   이름으로 ETW 세션을 중지한다 (logman stop -ets). 결과 종료 코드를 반환한다.
   E2/E7 에서는 일부러 중지시키고, E3 에서는 강제 종료 뒤 남은 세션을 지우는 데 쓴다.
#>
function Stop-EtwSession {
    param([Parameter(Mandatory = $true)][string]$TraceName, [Parameter(Mandatory = $true)][string]$Tag)
    $logman = Resolve-Tool "logman"
    $r = Invoke-Captured -Name ("logman-" + $Tag) -FilePath $logman -ArgumentList @("stop", $TraceName, "-ets") -TimeoutSec 30
    return $r.ExitCode
}

<#
 Invoke-WatchdogNow
   Cloud Scheduler 작업을 지금 한 번 실행한다 (2분 주기를 기다리지 않기 위해). 비동기로 시작된다.
#>
function Invoke-WatchdogNow {
    $r = Invoke-Gcloud -Name "watchdog-run" -ArgumentList @("scheduler", "jobs", "run", "edr-watchdog-job", ("--location=" + $script:Ctx.Region))
    if ($r.ExitCode -ne 0) { Write-Log ("watchdog 수동 실행 실패: " + (Get-HeadText -Text $r.StdErr -Lines 2)) "WARN" }
}

<#
 Add-DiscordCheck
   Discord 도착 여부는 스크립트가 볼 수 없어 사람에게 묻는다. 웹훅을 입력하지 않았으면 아무 것도 하지 않는다.
   y -> PASS / n -> FAIL / 그 밖(Enter, -Yes) -> MANUAL
#>
function Add-DiscordCheck {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Expect)
    if ($null -eq $script:Ctx.Webhook) { return }
    $ans = Confirm-Manual -Question ("Discord 채널에 " + $Expect + " 형태의 메시지가 도착했습니까?")
    if ($ans -eq "y") { Add-Result -Id $Id -Title "Discord 도착 확인" -Status PASS }
    elseif ($ans -eq "n") { Add-Result -Id $Id -Title "Discord 도착 확인" -Status FAIL -Detail "도착하지 않았다고 답했습니다. Function 로그(웹훅 전송 실패 문구)를 확인하세요." }
    else { Add-Result -Id $Id -Title "Discord 도착 확인" -Status MANUAL -Detail ("직접 확인: " + $Expect) }
}


# ==============================================================================
# E. 종단 간 시험
# ==============================================================================

function Invoke-StageE {
    $ctx = $script:Ctx
    $project = $ctx.ProjectId
    $region = $ctx.Region
    $exe = $ctx.Exe

    # ---- 사전 조건 -------------------------------------------------------------
    if (-not (Test-IsAdmin)) {
        Add-Result -Id "E1" -Title "수집 경로" -Status SKIP -Detail "ETW 세션을 만들려면 관리자 권한이 필요합니다."
        return
    }
    if (-not (Test-Path -LiteralPath $exe) -or -not (Test-Path -LiteralPath $ctx.KeyPath)) {
        Add-Result -Id "E1" -Title "수집 경로" -Status FAIL -Detail "실행 파일(A3) 또는 키 파일(C6)이 없습니다."
        return
    }

    # E1, E2, E7, E3 이 함께 쓰는 세션과 에이전트
    $sidA = Get-SessionId "e1"
    $sess = $null

    # ---- E1 수집 경로 -----------------------------------------------------------
    Write-Log ("E1: 에이전트 시작 (세션 " + $sidA + ")")
    $sess = Start-EdrSession -Sid $sidA -Tag "A"
    if (-not $sess) {
        Add-Result -Id "E1" -Title "수집 경로" -Status FAIL -Detail "에이전트가 시작되지 않았습니다 (E-A.err.txt 확인)."
        return
    }
    $marker = New-Marker
    [void](New-HarmlessActivity -Marker $marker)
    Write-Log "E1: 수집이 쌓이도록 2분 대기"
    Start-Sleep -Seconds 120

    # 6종이 모두 있고 heartbeat 가 약 10초마다 쌓였는지 (2분이면 12건 안팎이므로 3건 이상이면 통과)
    $needKinds = @("agent_start", "proc_existing", "proc_start", "proc_stop", "net", "heartbeat")
    $test1 = {
        param($m)
        $ok = $true
        foreach ($k in $needKinds) { if (-not $m.ContainsKey($k)) { $ok = $false } }
        if ($ok -and $m["heartbeat"] -lt 3) { $ok = $false }
        $ok
    }   # $needKinds 는 동적 범위로 읽는다
    $kinds = Wait-KindMap -Sid $sidA -Test $test1 -TimeoutSec 240
    if ($null -ne $kinds) {
        $summary = (($kinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { $_.Key + "=" + $_.Value }) -join ", ")
        Add-Result -Id "E1" -Title "수집 경로" -Status PASS -Detail ($summary + " (B4 의 비율과 비교해 보세요. 이미지 로드는 꺼져 있음)")
    }
    else {
        $last = (($script:LastKindMap.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { $_.Key + "=" + $_.Value }) -join ", ")
        Add-Result -Id "E1" -Title "수집 경로" -Status FAIL -Detail ("4분 안에 필요한 종류가 모두 도착하지 않음. 마지막 조회: " + $last)
        # 수집 경로 자체가 안 되면 뒤 시험이 의미 없다.
        [void](Stop-EdrAgent -Agent $sess.Agent -Force)
        [void](Stop-EtwSession -TraceName $sess.Ready.TraceName -Tag "E1-cleanup")
        return
    }

    # ---- E2 ETW 중지 경보 --------------------------------------------------------
    Write-Log "E2: 외부에서 ETW 세션 중지"
    $trace = $sess.Ready.TraceName
    $exit1 = Stop-EtwSession -TraceName $trace -Tag "E2"
    if ($exit1 -ne 0) {
        Add-Result -Id "E2" -Title "ETW 중지 경보" -Status FAIL -Detail ("logman stop 실패(종료 코드 " + $exit1 + ")")
    }
    else {
        $test2 = { param($m) $m.ContainsKey("etw_stopped") -and $m.ContainsKey("etw_restarted") }
        $k2 = Wait-KindMap -Sid $sidA -Test $test2 -TimeoutSec 240
        $alertOk = Wait-AlertCount -Sid $sidA -Reason "etw_stopped" -Min 1 -TimeoutSec 180
        $p2 = @()
        if ($null -eq $k2) { $p2 += "events 에 etw_stopped/etw_restarted 가 모두 도착하지 않음" }
        if (-not $alertOk) { $p2 += "alerts 에 etw_stopped 이력이 없음" }
        if ($p2.Count -eq 0) {
            Add-Result -Id "E2" -Title "ETW 중지 경보" -Status PASS -Detail "etw_stopped, etw_restarted 적재 및 alerts 이력 1건 확인"
            Add-DiscordCheck -Id "E2d" -Expect ("[EDR] etw_stopped | sid=" + $sidA)
        }
        else {
            Add-Result -Id "E2" -Title "ETW 중지 경보" -Status FAIL -Detail ($p2 -join "; ")
        }
    }
    $e2Passed = (@($script:Results | Where-Object { $_.Id -eq "E2" -and $_.Status -eq "PASS" }).Count -gt 0)

    # ---- E7 경보 중복 방지 (E2 직후, 30분 안) ---------------------------------------
    if (-not $e2Passed) {
        Add-Result -Id "E7" -Title "경보 중복 방지" -Status SKIP -Detail "E2 가 통과하지 않아 확인할 수 없습니다."
    }
    else {
        Write-Log "E7: ETW 세션을 한 번 더 중지"
        $exit2 = Stop-EtwSession -TraceName $trace -Tag "E7"
        if ($exit2 -ne 0) {
            Add-Result -Id "E7" -Title "경보 중복 방지" -Status FAIL -Detail ("두 번째 logman stop 실패(종료 코드 " + $exit2 + "). 재시작 뒤 세션 이름이 바뀌었을 수 있습니다.")
        }
        else {
            $test7 = { param($m) $m.ContainsKey("etw_stopped") -and $m["etw_stopped"] -ge 2 }
            $k7 = Wait-KindMap -Sid $sidA -Test $test7 -TimeoutSec 240
            if ($null -eq $k7) {
                Add-Result -Id "E7" -Title "경보 중복 방지" -Status FAIL -Detail "두 번째 etw_stopped 이벤트가 events 에 도착하지 않음"
            }
            else {
                # 이벤트가 적재된 뒤 Function 이 경보 여부를 판단할 시간을 준다.
                Start-Sleep -Seconds 60
                $n = Get-AlertCount -Sid $sidA -Reason "etw_stopped"
                if ($n -eq 1) {
                    Add-Result -Id "E7" -Title "경보 중복 방지" -Status PASS -Detail "etw_stopped 이벤트 2건, 경보 이력은 1건 (30분 안 중복 억제)"
                }
                else {
                    Add-Result -Id "E7" -Title "경보 중복 방지" -Status FAIL -Detail ("경보 이력이 " + $n + "건 (1건이어야 함)")
                }
            }
        }
    }

    # ---- E3 heartbeat 공백 경보 -----------------------------------------------------
    # agent_stop 없이 강제 종료한다. watchdog 은 마지막 heartbeat 가 30초(3 x 10초)보다 오래되면 알린다.
    Write-Log "E3: 에이전트 강제 종료 (agent_stop 없음)"
    $tKill = Get-Date
    [void](Stop-EdrAgent -Agent $sess.Agent -Force)
    [void](Stop-EtwSession -TraceName $trace -Tag "E3-cleanup")   # 강제 종료로 남은 커널 세션 정리
    Start-Sleep -Seconds 40
    Invoke-WatchdogNow
    $silenceOk = Wait-AlertCount -Sid $sidA -Reason "heartbeat_silence" -Min 1 -TimeoutSec 240
    $secs = [int]((Get-Date) - $tKill).TotalSeconds
    if ($silenceOk) {
        Add-Result -Id "E3" -Title "heartbeat 공백 경보" -Status PASS -Detail ("강제 종료 후 약 " + $secs + "초 시점에 heartbeat_silence 이력 확인")
        Add-DiscordCheck -Id "E3d" -Expect ("[EDR] heartbeat_silence | sid=" + $sidA)
    }
    else {
        Add-Result -Id "E3" -Title "heartbeat 공백 경보" -Status FAIL -Detail ("강제 종료 후 " + $secs + "초 동안 heartbeat_silence 이력이 생기지 않음 (watchdog 로그 확인)")
    }

    # 같은 세션 ID 로 다시 시작했다가 정상 종료해 agent_stop 을 남긴다 (반복 경보를 멈춘다).
    Write-Log "E3: 반복 경보를 멈추기 위해 같은 세션을 다시 시작했다가 정상 종료"
    $re = Start-EdrSession -Sid $sidA -Tag "A2"
    if ($re) {
        Start-Sleep -Seconds 15
        $howRe = Stop-EdrAgent -Agent $re.Agent
        Write-Log ("정리용 재시작 에이전트 종료 방식: " + $howRe)
    }

    # ---- E4 정상 종료는 경보 없음 ------------------------------------------------------
    $sidB = Get-SessionId "e4"
    Write-Log ("E4: 새 세션 " + $sidB + " 으로 1분 실행 후 Ctrl+C")
    $s4 = Start-EdrSession -Sid $sidB -Tag "B"
    if (-not $s4) {
        Add-Result -Id "E4" -Title "정상 종료는 경보 없음" -Status FAIL -Detail "에이전트가 시작되지 않았습니다."
    }
    else {
        Start-Sleep -Seconds 60
        $how4 = Stop-EdrAgent -Agent $s4.Agent
        # 종료 뒤 watchdog 이 최소 두 번(종료 반영 후) 돌도록 시간을 두고 수동 실행한다. 총 약 2분 30초.
        Start-Sleep -Seconds 45
        Invoke-WatchdogNow
        Start-Sleep -Seconds 75
        Invoke-WatchdogNow
        Start-Sleep -Seconds 30
        $test4 = { param($m) $m.ContainsKey("agent_stop") }
        $k4 = Wait-KindMap -Sid $sidB -Test $test4 -TimeoutSec 60
        $silence4 = Get-AlertCount -Sid $sidB -Reason "heartbeat_silence"
        $p4 = @()
        if ($how4 -ne "graceful") { $p4 += ("정상 종료가 아님(" + $how4 + ")") }
        if ($null -eq $k4) { $p4 += "events 에 agent_stop 이 없음" }
        if ($silence4 -gt 0) { $p4 += ("heartbeat_silence 경보 " + $silence4 + "건 (0건이어야 함)") }
        if ($p4.Count -eq 0) {
            Add-Result -Id "E4" -Title "정상 종료는 경보 없음" -Status PASS -Detail "agent_stop 적재, heartbeat_silence 경보 0건"
        }
        elseif ($how4 -eq "ctrlc-failed") {
            Add-Result -Id "E4" -Title "정상 종료는 경보 없음" -Status SKIP -Detail "Ctrl+C 신호를 보내지 못해 정상 종료를 만들 수 없었습니다. 수동으로 확인하세요."
        }
        else {
            Add-Result -Id "E4" -Title "정상 종료는 경보 없음" -Status FAIL -Detail ($p4 -join "; ")
        }
    }

    # ---- E5 전송 중단과 복구 --------------------------------------------------------------
    # 에이전트 실행 파일만 막는 아웃바운드 규칙을 만들고 90초 뒤 지운다.
    $sidC = Get-SessionId "e5"
    Write-Log ("E5: 새 세션 " + $sidC + " 시작")
    $s5 = Start-EdrSession -Sid $sidC -Tag "C"
    if (-not $s5) {
        Add-Result -Id "E5" -Title "전송 중단과 복구" -Status FAIL -Detail "에이전트가 시작되지 않았습니다."
    }
    else {
        Start-Sleep -Seconds 30   # 정상 전송이 먼저 쌓이게 한다
        $ruleName = "edr-test-block"
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $exe -Action Block | Out-Null
            if (-not $ctx.FirewallRules) { $ctx.FirewallRules = @() }
            $ctx.FirewallRules += $ruleName
            Write-Log "E5: 전송 차단 90초"
            Start-Sleep -Seconds 90
        }
        finally {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            $ctx.FirewallRules = @($ctx.FirewallRules | Where-Object { $_ -ne $ruleName })
        }
        Write-Log "E5: 차단 해제. 복구 후 heartbeat 의 dropped_send 를 기다립니다."

        # 복구 뒤 heartbeat 에 dropped_send 가 0보다 크게 실려 와야 한다 (누락분을 설명하는 카운터).
        $sqlDrop = "SELECT MAX(dropped_send) AS ds, COUNT(*) AS n FROM " + (Get-BqTable "events") +
                   " WHERE sid = '" + $sidC + "' AND kind = 'heartbeat' AND recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)"
        $condDrop = { param($rs) (@($rs).Count -gt 0) -and ($null -ne @($rs)[0].ds) -and ([int64]@($rs)[0].ds -gt 0) }
        $dropRows = Wait-BqRows -Name "E5-dropped" -Sql $sqlDrop -Condition $condDrop -TimeoutSec 240 -IntervalSec 15

        # seq_gap 이 오지 않는지 확인하기 전에, watchdog 이 복구 이후 상태로 두 번 돌 시간을 준다.
        Invoke-WatchdogNow
        Start-Sleep -Seconds 100
        Invoke-WatchdogNow
        Start-Sleep -Seconds 30
        $gap = Get-AlertCount -Sid $sidC -Reason "seq_gap"
        $alive = (-not $s5.Agent.Process.HasExited)

        $p5 = @()
        if ($null -eq $dropRows) { $p5 += "복구 뒤 heartbeat 의 dropped_send 가 0 이하(차단이 적용되지 않았거나 연결이 유지됐을 수 있음)" }
        if ($gap -gt 0) { $p5 += ("seq_gap 경보 " + $gap + "건 (드롭 카운터로 설명되어야 하므로 0건이어야 함)") }
        if (-not $alive) { $p5 += "에이전트가 종료됨" }
        if ($p5.Count -eq 0) {
            Add-Result -Id "E5" -Title "전송 중단과 복구" -Status PASS `
                -Detail ("복구 후 dropped_send=" + @($dropRows)[0].ds + ", seq_gap 경보 0건, 에이전트 계속 실행 (차단 중의 heartbeat_silence 는 정상)")
        }
        else {
            Add-Result -Id "E5" -Title "전송 중단과 복구" -Status FAIL -Detail ($p5 -join "; ")
        }
        [void](Stop-EdrAgent -Agent $s5.Agent)
    }

    # ---- E6 위조 로그는 거부 -------------------------------------------------------------
    # 로그인한 사용자 계정으로 형식이 잘못된 항목(kind 가 허용 목록에 없음)을 Logging API 로 직접 기록한다.
    # gcloud logging write 는 JSON 따옴표가 .cmd 를 거치며 깨지므로 REST 로 보낸다.
    # 접근 토큰은 변수에만 두고 어디에도 기록하지 않는다.
    $forgedSid = "forged" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    $sent = $false
    $sendErr = ""
    try {
        $gcloud = Resolve-Tool "gcloud"
        $tok = ((& $gcloud auth print-access-token) | Select-Object -First 1)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $body = @{
            entries = @(@{
                logName     = ("projects/" + $project + "/logs/lab_malware")
                resource    = @{ type = "global" }
                jsonPayload = @{ v = 1; sid = $forgedSid; seq = 1; ts_ms = 1; kind = "evil" }
            })
        } | ConvertTo-Json -Depth 6 -Compress
        [void](Invoke-RestMethod -Method Post -Uri "https://logging.googleapis.com/v2/entries:write" `
            -Headers @{ Authorization = ("Bearer " + $tok) } -ContentType "application/json" -Body $body)
        $sent = $true
    }
    catch {
        $sendErr = $_.Exception.Message
    }
    finally {
        $tok = $null
    }
    if (-not $sent) {
        Add-Result -Id "E6" -Title "위조 로그는 거부" -Status FAIL -Detail ("위조 로그를 기록하지 못했습니다: " + $sendErr)
    }
    else {
        $invalidOk = Wait-AlertCount -Sid $forgedSid -Reason "invalid_event" -Min 1 -TimeoutSec 240
        $sqlForged = "SELECT COUNT(*) AS n FROM " + (Get-BqTable "events") +
                     " WHERE sid = '" + $forgedSid + "' AND recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)"
        $inEvents = [int]@(Invoke-BqQuery -Name "E6-events" -Sql $sqlForged)[0].n
        $p6 = @()
        if (-not $invalidOk) { $p6 += "alerts 에 invalid_event 이력이 없음" }
        if ($inEvents -gt 0) { $p6 += ("위조 항목이 events 에 " + $inEvents + "건 적재됨") }
        if ($p6.Count -eq 0) {
            Add-Result -Id "E6" -Title "위조 로그는 거부" -Status PASS -Detail "invalid_event 경보 이력 확인, events 에는 적재되지 않음"
            Add-DiscordCheck -Id "E6d" -Expect ("[EDR] invalid_event | sid=" + $forgedSid + " | 사유 코드: unknown_kind")
        }
        else {
            Add-Result -Id "E6" -Title "위조 로그는 거부" -Status FAIL -Detail ($p6 -join "; ")
        }
    }

    # ---- E8 이미지 로드를 켠 양 측정 ---------------------------------------------------------
    # 비용 추정용 수치를 기록한다. 이 PC 는 분석용 VM 보다 이벤트가 훨씬 많으므로 값은 참고용이다.
    $minutes = [int]$ctx.ImageLoadMinutes
    $sidD = Get-SessionId "e8"
    Write-Log ("E8: 이미지 로드를 켜고 " + $minutes + "분 측정 (세션 " + $sidD + ")")
    $s8 = Start-EdrSession -Sid $sidD -Tag "D" -ImageLoads $true
    if (-not $s8) {
        Add-Result -Id "E8" -Title "이미지 로드를 켠 양 측정" -Status FAIL -Detail "에이전트가 시작되지 않았습니다."
    }
    else {
        $t8 = Get-Date
        for ($i = 1; $i -le $minutes; $i++) {
            Start-Sleep -Seconds 60
            Write-Log ("E8: " + $i + "/" + $minutes + "분 경과")
        }
        [void](Stop-EdrAgent -Agent $s8.Agent)
        $runMin = ((Get-Date) - $t8).TotalSeconds / 60
        Write-Log "E8: 적재가 끝나기를 기다리는 중 (최대 4분)"
        $test8 = { param($m) $m.ContainsKey("agent_stop") }
        [void](Wait-KindMap -Sid $sidD -Test $test8 -TimeoutSec 240)
        $sql8 = "SELECT COUNT(*) AS rows_total, SUM(LENGTH(TO_JSON_STRING(payload))) AS payload_bytes, COUNTIF(kind = 'image_load') AS image_rows FROM " +
                (Get-BqTable "events") + " WHERE sid = '" + $sidD + "' AND recv_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)"
        $r8 = @(Invoke-BqQuery -Name "E8-volume" -Sql $sql8)
        $rowsTotal = 0
        $bytes = 0
        $imgRows = 0
        if ($r8.Count -gt 0) {
            $rowsTotal = [int64]$r8[0].rows_total
            if ($null -ne $r8[0].payload_bytes) { $bytes = [int64]$r8[0].payload_bytes }
            $imgRows = [int64]$r8[0].image_rows
        }
        if ($rowsTotal -gt 0 -and $imgRows -gt 0 -and $runMin -gt 0) {
            $perMinRows = [math]::Round($rowsTotal / $runMin, 0)
            $perMinKiB = [math]::Round(($bytes / 1KB) / $runMin, 1)
            $perHourMiB = [math]::Round(($bytes / 1MB) / $runMin * 60, 1)
            Add-Result -Id "E8" -Title "이미지 로드를 켠 양 측정" -Status PASS `
                -Detail ("분당 약 " + $perMinRows + "행, " + $perMinKiB + " KiB (시간당 약 " + $perHourMiB + " MiB), image_load " + $imgRows + "행 / 총 " + $rowsTotal + "행. " +
                         "분당 값 x 월 분석 시간을 GCP 요금표와 비교해 월 5,000원 안팎인지 판단하세요.")
        }
        else {
            Add-Result -Id "E8" -Title "이미지 로드를 켠 양 측정" -Status FAIL `
                -Detail ("행 수=" + $rowsTotal + ", image_load 행=" + $imgRows + " (이미지 로드 이벤트가 적재되지 않았거나 도착이 늦음)")
        }
    }
}
