<#
================================================================================
 20_stage-local.ps1 - 체크리스트 P(준비), A(자동 테스트), B(로컬 수집 확인) 단계

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증).

 이 파일은 GCP 에 접속하지 않습니다 (P 단계에서 -ProjectId 를 준 경우의 gcloud 조회는 예외).
 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 점 소싱으로 불러오며, 아래 세 함수를 단계 순서대로 호출합니다.

   Invoke-StageP   P1~P6  준비 확인 (관리자 권한, 도구, GCP 로그인, 세션 이름)
   Invoke-StageA   A1~A3  cargo test, python -m unittest, cargo build --release
   Invoke-StageB   B1~B8  edr-lite --dry-run 수집을 실제로 돌려 이벤트를 검증

 체크리스트 문서(EDR_일반PC_테스트_체크리스트.md)의 같은 번호 항목과 1:1 로 대응합니다.
 문서와 달라진 점
   - 활동 생성에 메모장 대신 `cmd /c echo <표식>` 을 씁니다. Windows 11 의 메모장은 시작
     프로세스와 실제 프로세스가 달라 자동으로 닫기 어렵고, 표식 문자열이 명령줄에 남아
     "이번 실행이 만든 이벤트"를 정확히 찾을 수 있기 때문입니다.
   - 에이전트 출력은 cmd.exe 리다이렉트로 저장해 UTF-8 그대로이므로 파일 크기가 실제
     이벤트 크기입니다 (PowerShell 5.1 의 `>` 는 UTF-16 으로 저장해 두 배가 된다).
================================================================================
#>


# ==============================================================================
# P. 준비
# ==============================================================================

function Invoke-StageP {
    $ctx = $script:Ctx
    $needAdmin = ($ctx.Stages -contains "B")   # B 단계(ETW)만 관리자 권한이 필요하다

    # ---- P1 관리자 권한 ----------------------------------------------------
    # ETW 커널 세션은 관리자 권한이 없으면 시작되지 않는다.
    if (Test-IsAdmin) {
        Add-Result -Id "P1" -Title "관리자 PowerShell 로 실행 중" -Status PASS
    }
    elseif ($needAdmin) {
        Add-Result -Id "P1" -Title "관리자 PowerShell 로 실행 중" -Status FAIL `
            -Detail "B 단계(ETW)는 관리자 권한이 필요합니다. 관리자 PowerShell 에서 다시 실행하세요."
    }
    else {
        Add-Result -Id "P1" -Title "관리자 PowerShell 로 실행 중" -Status SKIP `
            -Detail "선택한 단계에는 관리자 권한이 필요하지 않습니다."
    }

    # ---- P2 도구 설치 -------------------------------------------------------
    # 필수: cargo, python (A 단계). 선택: gcloud, bq (ProjectId 를 준 경우 필수).
    $needGcloud = ($ctx.ProjectId -ne "")
    $toolSpecs = @(
        @{ Name = "cargo";  Args = @("--version"); Pattern = "cargo \d";              Required = $true },
        # python 은 Microsoft Store 안내용 가짜 python.exe 일 수 있어, 버전 문구까지 확인한다.
        @{ Name = "python"; Args = @("--version"); Pattern = "Python \d";             Required = $true },
        @{ Name = "gcloud"; Args = @("--version"); Pattern = "Google Cloud SDK";      Required = $needGcloud },
        @{ Name = "bq";     Args = @("version");   Pattern = "BigQuery CLI";          Required = $needGcloud }
    )
    $missing = @()
    $found = @()
    foreach ($t in $toolSpecs) {
        $path = Resolve-Tool $t.Name
        $ok = $false
        if ($path) {
            $r = Invoke-Captured -Name ("ver-" + $t.Name) -FilePath $path -ArgumentList $t.Args -TimeoutSec 60
            if ($r.Text -match $t.Pattern) {
                $ok = $true
                # 버전 첫 줄만 요약에 쓴다.
                $first = ($r.Text -split "`r?`n" | Where-Object { $_ -match $t.Pattern } | Select-Object -First 1)
                $found += ($t.Name + ": " + $first.Trim())
            }
        }
        if (-not $ok -and $t.Required) { $missing += $t.Name }
        if (-not $ok -and -not $t.Required) { $found += ($t.Name + ": 없음(선택)") }
    }
    if ($missing.Count -eq 0) {
        Add-Result -Id "P2" -Title "필수 도구가 설치됨" -Status PASS -Detail ($found -join " | ")
    }
    else {
        Add-Result -Id "P2" -Title "필수 도구가 설치됨" -Status FAIL `
            -Detail ("없는 도구: " + ($missing -join ", ") + " (새 PowerShell 창을 열어 PATH 를 갱신했는지 확인)")
    }

    # ---- P3, P4 GCP 프로젝트와 로그인 (ProjectId 를 준 경우만) ---------------
    $gcloud = Resolve-Tool "gcloud"
    if ($ctx.ProjectId -eq "") {
        Add-Result -Id "P3" -Title "GCP 테스트 프로젝트 확인" -Status SKIP -Detail "-ProjectId 가 없어 로컬 단계만 실행합니다."
        Add-Result -Id "P4" -Title "gcloud 로그인 확인" -Status SKIP -Detail "-ProjectId 가 없어 로컬 단계만 실행합니다."
    }
    elseif (-not $gcloud) {
        Add-Result -Id "P3" -Title "GCP 테스트 프로젝트 확인" -Status FAIL -Detail "gcloud 를 찾을 수 없습니다."
        Add-Result -Id "P4" -Title "gcloud 로그인 확인" -Status FAIL -Detail "gcloud 를 찾을 수 없습니다."
    }
    else {
        # P4 활성 계정 확인: ACTIVE 상태인 계정이 하나라도 있어야 한다.
        $auth = Invoke-Captured -Name "gcloud-auth" -FilePath $gcloud `
            -ArgumentList @("auth", "list", "--filter=status:ACTIVE", "--format=value(account)") -TimeoutSec 60
        if ($auth.ExitCode -eq 0 -and $auth.StdOut.Trim() -ne "") {
            Add-Result -Id "P4" -Title "gcloud 로그인 확인" -Status PASS -Detail ("활성 계정: " + $auth.StdOut.Trim().Split("`n")[0].Trim())
        }
        else {
            Add-Result -Id "P4" -Title "gcloud 로그인 확인" -Status FAIL -Detail "활성 계정이 없습니다. gcloud auth login 을 먼저 실행하세요."
        }

        # P3 프로젝트가 존재하고 접근 가능한지 확인한다. (결제 연결 여부는 여기서 확인하지 않는다)
        $proj = Invoke-Captured -Name "gcloud-project" -FilePath $gcloud `
            -ArgumentList @("projects", "describe", $ctx.ProjectId, "--format=value(projectId)") -TimeoutSec 60
        if ($proj.ExitCode -eq 0 -and $proj.StdOut.Trim() -eq $ctx.ProjectId) {
            Add-Result -Id "P3" -Title "GCP 테스트 프로젝트 확인" -Status PASS -Detail "프로젝트에 접근할 수 있습니다. 결제 연결은 콘솔에서 직접 확인하세요."
        }
        else {
            Add-Result -Id "P3" -Title "GCP 테스트 프로젝트 확인" -Status FAIL -Detail "프로젝트를 조회하지 못했습니다(ID 오타, 권한, 로그인 확인)."
        }
    }

    # ---- P5 Discord 웹훅 ----------------------------------------------------
    # 웹훅 주소는 비밀 값이라 로그와 화면에 남기지 않는다. 실행 시작 때 15_prompts.ps1 이 숨김 입력으로
    # 받으며, 사람이 할 일은 테스트 서버에서 웹훅을 미리 만들어 두는 것뿐이다.
    Add-Result -Id "P5" -Title "테스트용 Discord 웹훅 준비" -Status MANUAL `
        -Detail "테스트 서버에서 웹훅을 만들어 두세요. 주소는 실행 시작 때 숨김 입력창에만 붙여 넣습니다(비우면 알림 없이 진행)."

    # ---- P6 세션 이름 -------------------------------------------------------
    Add-Result -Id "P6" -Title "테스트 세션 이름 결정" -Status PASS -Detail ("이번 실행 기본 세션 이름: " + $ctx.SessionName)
}


# ==============================================================================
# A. 자동 테스트와 빌드
# ==============================================================================

function Invoke-StageA {
    $ctx = $script:Ctx
    $cargo  = Resolve-Tool "cargo"
    $python = Resolve-Tool "python"

    # ---- A1 에이전트 단위 테스트 ---------------------------------------------
    # cargo test 는 처음 실행하면 의존성을 내려받아 컴파일하느라 오래 걸린다 (제한 시간 15분).
    if (-not $cargo) {
        Add-Result -Id "A1" -Title "에이전트 단위 테스트(cargo test)" -Status FAIL -Detail "cargo 를 찾을 수 없습니다."
    }
    else {
        Write-Log "cargo test 실행 중... (처음에는 수 분 걸릴 수 있습니다)"
        $r = Invoke-Captured -Name "A1-cargo-test" -FilePath $cargo -ArgumentList @("test") `
            -WorkingDirectory $ctx.RepoRoot -TimeoutSec 900
        # 결과 줄 예: "test result: ok. 23 passed; 0 failed; 0 ignored; ..."
        # 테스트 대상이 여러 개면 줄이 여러 개이므로 모두 더한다.
        $passed = 0
        $failed = 0
        foreach ($m in [regex]::Matches($r.Text, "test result: \w+\. (\d+) passed; (\d+) failed")) {
            $passed += [int]$m.Groups[1].Value
            $failed += [int]$m.Groups[2].Value
        }
        if ($r.TimedOut) {
            Add-Result -Id "A1" -Title "에이전트 단위 테스트(cargo test)" -Status FAIL -Detail "제한 시간(15분)을 넘겨 중단했습니다."
        }
        elseif ($r.ExitCode -eq 0 -and $failed -eq 0 -and $passed -gt 0) {
            Add-Result -Id "A1" -Title "에이전트 단위 테스트(cargo test)" -Status PASS -Detail ("$passed 개 통과")
        }
        else {
            Add-Result -Id "A1" -Title "에이전트 단위 테스트(cargo test)" -Status FAIL `
                -Detail ("통과 $passed / 실패 $failed / 종료 코드 " + $r.ExitCode + " (A1-cargo-test.err.txt 확인)")
        }
    }

    # ---- A2 Function 단위 테스트 ---------------------------------------------
    # python -m unittest 의 결과("Ran N tests ... OK")는 stderr 로 나온다. 표준 라이브러리만 쓰므로
    # 패키지 설치는 필요 없다.
    $fnDir = Join-Path $ctx.RepoRoot "gcp\functions\edr_monitor"
    if (-not $python) {
        Add-Result -Id "A2" -Title "Function 단위 테스트(python -m unittest)" -Status FAIL -Detail "python 을 찾을 수 없습니다."
    }
    elseif (-not (Test-Path -LiteralPath $fnDir)) {
        Add-Result -Id "A2" -Title "Function 단위 테스트(python -m unittest)" -Status FAIL -Detail ("폴더가 없습니다: " + $fnDir)
    }
    else {
        $r = Invoke-Captured -Name "A2-unittest" -FilePath $python -ArgumentList @("-m", "unittest") `
            -WorkingDirectory $fnDir -TimeoutSec 300
        $ran = ""
        if ($r.Text -match "Ran (\d+) tests?") { $ran = $Matches[1] }
        if ($r.ExitCode -eq 0 -and $r.Text -match "(?m)^OK\s*$") {
            Add-Result -Id "A2" -Title "Function 단위 테스트(python -m unittest)" -Status PASS -Detail ("$ran 개 통과")
        }
        else {
            Add-Result -Id "A2" -Title "Function 단위 테스트(python -m unittest)" -Status FAIL `
                -Detail ("종료 코드 " + $r.ExitCode + " (A2-unittest.err.txt 확인)")
        }
    }

    # ---- A3 릴리스 빌드 ------------------------------------------------------
    # B 단계가 쓸 target\release\edr-lite.exe 를 만든다.
    if (-not $cargo) {
        Add-Result -Id "A3" -Title "릴리스 빌드(cargo build --release)" -Status FAIL -Detail "cargo 를 찾을 수 없습니다."
    }
    else {
        Write-Log "cargo build --release 실행 중... (처음에는 수 분 걸릴 수 있습니다)"
        $r = Invoke-Captured -Name "A3-cargo-build" -FilePath $cargo -ArgumentList @("build", "--release") `
            -WorkingDirectory $ctx.RepoRoot -TimeoutSec 1800
        if ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath $ctx.Exe)) {
            $size = [math]::Round((Get-Item -LiteralPath $ctx.Exe).Length / 1MB, 1)
            Add-Result -Id "A3" -Title "릴리스 빌드(cargo build --release)" -Status PASS -Detail ("edr-lite.exe 생성 (" + $size + " MB)")
        }
        else {
            Add-Result -Id "A3" -Title "릴리스 빌드(cargo build --release)" -Status FAIL `
                -Detail ("종료 코드 " + $r.ExitCode + " (A3-cargo-build.err.txt 확인)")
        }
    }
}


# ==============================================================================
# B. 로컬 수집 확인 (--dry-run)
# ==============================================================================

<#
 New-HarmlessActivity
   에이전트가 수집할 "무해한 활동"을 만든다.

   1) cmd /c echo <표식>  : proc_start / proc_stop 이벤트. 표식이 명령줄(cmdline)에 남는다.
   2) curl.exe https://example.com : TCP 443 연결 -> net(tcp connect) 이벤트
   3) Resolve-DnsName example.org  : DNS 질의(UDP 53) -> net(udp send) 이벤트.
      보통 DNS 클라이언트 서비스(svchost)가 보내므로 이벤트의 PID 는 서비스 프로세스일 수 있다.

   ping 은 ICMP 라서 수집기(TCP/UDP 만 봄)가 보지 못하므로 쓰지 않는다.
   반환: Marker 와 curl 종료 코드 (인터넷이 없으면 0 이 아님)
#>
function New-HarmlessActivity {
    param([Parameter(Mandatory = $true)][string]$Marker)

    # 1) 표식이 든 cmd 실행
    $cmd = $env:ComSpec
    [void](Invoke-Captured -Name ("activity-cmd-" + $Marker) -FilePath $cmd -ArgumentList @("/c", ("echo " + $Marker)) -TimeoutSec 20)

    # 2) curl: 응답 본문은 버린다(-o NUL). 인터넷이 없어도 연결 시도 자체가 이벤트가 될 수 있다.
    $curlExit = $null
    $curl = Resolve-Tool "curl"
    if ($curl) {
        $r = Invoke-Captured -Name ("activity-curl-" + $Marker) -FilePath $curl `
            -ArgumentList @("-s", "-o", "NUL", "--max-time", "20", "https://example.com") -TimeoutSec 40
        $curlExit = $r.ExitCode
    }

    # 3) DNS 질의: cmdlet 이 없는 환경이나 오프라인이면 실패할 수 있으므로 오류를 무시한다.
    try {
        Resolve-DnsName -Name "example.org" -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log ("DNS 질의 실패(무시): " + $_.Exception.Message) "WARN"
    }

    return [pscustomobject]@{ Marker = $Marker; CurlExit = $curlExit }
}

<#
 New-Marker
   "이번 실행이 만든 이벤트"를 구분하기 위한 표식 문자열을 만든다. 예: EDR_TEST_3F9A12BC
#>
function New-Marker {
    return ("EDR_TEST_" + [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper())
}

function Invoke-StageB {
    $ctx = $script:Ctx
    $exe = $ctx.Exe

    # 사전 조건: 실행 파일과 관리자 권한. 없으면 B 전체를 건너뛴다(원인은 P1, A3 결과를 본다).
    if (-not (Test-Path -LiteralPath $exe)) {
        Add-Result -Id "B1" -Title "에이전트 수집 시작(--dry-run)" -Status FAIL -Detail ("실행 파일이 없습니다: " + $exe + " (A3 빌드 먼저)")
        return
    }
    if (-not (Test-IsAdmin)) {
        Add-Result -Id "B1" -Title "에이전트 수집 시작(--dry-run)" -Status SKIP -Detail "관리자 권한이 아니라 ETW 세션을 만들 수 없습니다."
        return
    }

    # ============================ 1회차: 수집과 검증 ============================
    $marker1 = New-Marker

    # ---- B1 수집 시작 --------------------------------------------------------
    Write-Log "B1: edr-lite --dry-run 시작"
    $agent = Start-EdrAgent -Exe $exe -AgentArgs "--dry-run" -Tag "B-dry1"
    $ready = Wait-AgentReady -Agent $agent -TimeoutSec 30
    if (-not $ready) {
        $errHead = ((Read-SharedLines -Path $agent.ErrFile) | Select-Object -First 5) -join " / "
        Add-Result -Id "B1" -Title "에이전트 수집 시작(--dry-run)" -Status FAIL -Detail ("30초 안에 시작 메시지가 없습니다. stderr: " + $errHead)
        [void](Stop-EdrAgent -Agent $agent -Force)
        return
    }
    Add-Result -Id "B1" -Title "에이전트 수집 시작(--dry-run)" -Status PASS `
        -Detail ("ETW 세션=" + $ready.TraceName + ", 에이전트 PID=" + $ready.AgentPid)

    # ---- B2 무해한 활동 생성 -------------------------------------------------
    Write-Log "B2: 무해한 활동 생성 (표식 $marker1)"
    $activity = New-HarmlessActivity -Marker $marker1
    Add-Result -Id "B2" -Title "무해한 활동 생성" -Status PASS `
        -Detail ("표식=" + $marker1 + ", curl 종료 코드=" + $activity.CurlExit)

    # 수집이 쌓이도록 기다린다. heartbeat 는 10초 주기이므로 최소 25초 이상 둬야 2건 이상 확인할 수 있다.
    $waitSec = [math]::Max($script:DryRunSeconds, 25)
    $elapsed = ((Get-Date) - $agent.StartedAt).TotalSeconds
    $remain = [int]($waitSec - $elapsed)
    if ($remain -gt 0) {
        Write-Log ("수집 대기 " + $remain + "초...")
        Start-Sleep -Seconds $remain
    }

    # ---- B3 정상 종료 --------------------------------------------------------
    # Ctrl+C 를 보내 정상 종료를 시도한다. 종료 시 agent_stop(reason=signal) 이 기록되어야 한다.
    $how = Stop-EdrAgent -Agent $agent
    $runSeconds = ((Get-Date) - $agent.StartedAt).TotalSeconds
    $errText = (Read-SharedLines -Path $agent.ErrFile) -join "`n"
    $lines = Read-SharedLines -Path $agent.OutFile

    $hasStop = ($lines | Where-Object { $_ -match '"kind":"agent_stop"' } | Select-Object -First 1)
    if ($how -eq "graceful" -and $errText -match "종료 중" -and $hasStop) {
        Add-Result -Id "B3" -Title "Ctrl+C 정상 종료와 agent_stop 기록" -Status PASS -Detail "정상 종료됨"
    }
    elseif ($how -eq "ctrlc-failed") {
        Add-Result -Id "B3" -Title "Ctrl+C 정상 종료와 agent_stop 기록" -Status SKIP `
            -Detail "Ctrl+C 신호를 보내지 못해 강제 종료했습니다. 정상 종료는 관리자 창에서 직접 Ctrl+C 로 확인하세요."
    }
    else {
        Add-Result -Id "B3" -Title "Ctrl+C 정상 종료와 agent_stop 기록" -Status FAIL `
            -Detail ("종료 방식=" + $how + ", 종료 메시지=" + [bool]($errText -match "종료 중") + ", agent_stop=" + [bool]$hasStop)
    }

    # ---- B4 종류별 집계와 분량 -------------------------------------------------
    $kinds = Get-KindCounts -Lines $lines
    $required = @("agent_start", "proc_existing", "proc_start", "proc_stop", "image_load", "net", "heartbeat")
    $absent = @($required | Where-Object { -not $kinds.ContainsKey($_) })
    $summaryText = (($kinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { $_.Key + "=" + $_.Value }) -join ", ")
    $bytes = (Get-Item -LiteralPath $agent.OutFile).Length
    $perMinEvents = [int]($lines.Count / ($runSeconds / 60))
    $perMinKiB = [math]::Round(($bytes / 1KB) / ($runSeconds / 60), 1)
    $volume = ("총 " + $lines.Count + "건, " + [math]::Round($bytes / 1KB, 1) + " KiB, 약 분당 " + $perMinEvents + "건 / " + $perMinKiB + " KiB (UTF-8 기준)")
    if ($absent.Count -eq 0) {
        Add-Result -Id "B4" -Title "이벤트 종류별 집계와 분량" -Status PASS -Detail ($summaryText + " | " + $volume)
    }
    else {
        Add-Result -Id "B4" -Title "이벤트 종류별 집계와 분량" -Status FAIL -Detail ("없는 종류: " + ($absent -join ", ") + " | " + $summaryText)
    }

    # ---- B5 필드 확인 ---------------------------------------------------------
    # (a) 모든 줄이 공통 필드(v, sid, seq, ts_ms) 뒤에 kind 가 오는 형태인지
    # (b) seq 가 중복 없이 1부터 시작하는지
    # (c) 표식이 든 proc_start 에 pid, ppid, image, cmdline 이 있는지
    # (d) 443 포트 net 이벤트에 필수 필드가 있는지
    $envelope = New-Object System.Text.RegularExpressions.Regex('^\{"v":1,"sid":"[^"]*","seq":(\d+),"ts_ms":\d+,"kind":"')
    $badLines = 0
    $seqSet = New-Object System.Collections.Generic.HashSet[long]
    $dupSeq = 0
    foreach ($line in $lines) {
        $m = $envelope.Match($line)
        if (-not $m.Success) { $badLines++; continue }
        if (-not $seqSet.Add([long]$m.Groups[1].Value)) { $dupSeq++ }
    }
    # 강제 종료로 마지막 줄이 잘렸을 수 있어, 정상 종료가 아니면 형식 오류 1줄까지 허용한다.
    $badLimit = 0
    if ($how -ne "graceful") { $badLimit = 1 }
    $minSeq = 0
    if ($seqSet.Count -gt 0) { $minSeq = ($seqSet | Measure-Object -Minimum).Minimum }

    $procLine = $lines | Where-Object { $_ -match '"kind":"proc_start"' -and $_ -match $marker1 } | Select-Object -First 1
    $procOk = $false
    if ($procLine) {
        $procOk = ($procLine -match '"pid":\d+' -and $procLine -match '"ppid":\d+' -and $procLine -match '"image":"' -and $procLine -match '"cmdline":"')
    }
    $netLine = $lines | Where-Object { $_ -match '"kind":"net"' -and $_ -match '"dport":443' } | Select-Object -First 1
    $netOk = $false
    if ($netLine) {
        $netOk = ($netLine -match '"proto":"' -and $netLine -match '"op":"' -and $netLine -match '"src":"' -and
                  $netLine -match '"sport":\d+' -and $netLine -match '"dst":"' -and $netLine -match '"dport":\d+')
    }

    $problems = @()
    if ($badLines -gt $badLimit) { $problems += ("공통 필드 형식이 맞지 않는 줄 " + $badLines + "개") }
    if ($dupSeq -gt 0) { $problems += ("seq 중복 " + $dupSeq + "개") }
    if ($minSeq -ne 1) { $problems += ("seq 최솟값이 1이 아님(" + $minSeq + ")") }
    if (-not $procOk) { $problems += "표식이 든 proc_start 가 없거나 필드가 부족함" }
    $netNote = ""
    if (-not $netLine) {
        # 443 연결이 없을 때: curl 이 실패했다면(인터넷 없음) 이 확인만 건너뛴다.
        if ($activity.CurlExit -ne 0) { $netNote = "(curl 실패로 443 net 확인은 건너뜀)" }
        else { $problems += "dport 443 net 이벤트가 없음" }
    }
    elseif (-not $netOk) {
        $problems += "net 이벤트 필드가 부족함"
    }
    if ($problems.Count -eq 0) {
        Add-Result -Id "B5" -Title "이벤트 필드와 seq 확인" -Status PASS -Detail ("공통 필드, seq(1부터 중복 없음), proc_start, net 확인 " + $netNote)
    }
    else {
        Add-Result -Id "B5" -Title "이벤트 필드와 seq 확인" -Status FAIL -Detail ($problems -join "; ")
    }

    # ---- B6 heartbeat 확인 ----------------------------------------------------
    $hb = @($lines | Where-Object { $_ -match '"kind":"heartbeat"' })
    $hbProblems = @()
    if ($hb.Count -lt 2) { $hbProblems += ("heartbeat 가 " + $hb.Count + "건뿐임 (2건 이상 필요)") }
    foreach ($h in $hb) {
        if ($h -notmatch '"etw_alive":true')   { $hbProblems += "etw_alive 가 true 가 아닌 heartbeat 있음"; break }
    }
    foreach ($h in $hb) {
        if ($h -notmatch '"etw_restarts":0')   { $hbProblems += "etw_restarts 가 0 이 아닌 heartbeat 있음"; break }
    }
    foreach ($h in $hb) {
        if ($h -notmatch '"dropped_queue":0' -or $h -notmatch '"dropped_send":0') { $hbProblems += "드롭 카운터가 0 이 아닌 heartbeat 있음"; break }
    }
    # 파싱 오류 비율: 마지막 heartbeat 의 parse_errors / emitted
    $parseErr = 0
    $emitted = 0
    if ($hb.Count -gt 0) {
        $last = $hb[$hb.Count - 1]
        if ($last -match '"parse_errors":(\d+)') { $parseErr = [int]$Matches[1] }
        if ($last -match '"emitted":(\d+)')      { $emitted  = [int]$Matches[1] }
        if ($emitted -gt 0 -and ($parseErr / $emitted) -ge 0.05) { $hbProblems += ("parse_errors 비율이 5% 이상 (" + $parseErr + "/" + $emitted + ")") }
    }
    if ($hbProblems.Count -eq 0) {
        Add-Result -Id "B6" -Title "heartbeat 상태 확인" -Status PASS -Detail ("heartbeat " + $hb.Count + "건, parse_errors " + $parseErr + "/" + $emitted)
    }
    else {
        Add-Result -Id "B6" -Title "heartbeat 상태 확인" -Status FAIL -Detail ($hbProblems -join "; ")
    }

    # ---- B7 에이전트 자신의 PID 제외 --------------------------------------------
    # net 과 image_load 이벤트의 pid 가 에이전트 PID 와 같은 줄이 없어야 한다.
    # ("pid" 앞의 따옴표까지 패턴에 넣어 "ppid" 와 헷갈리지 않게 한다.)
    if ($ready.AgentPid -gt 0) {
        $selfPattern = '"kind":"(net|image_load)".*"pid":' + $ready.AgentPid + '[,}]'
        $selfHits = @($lines | Where-Object { $_ -match $selfPattern })
        if ($selfHits.Count -eq 0) {
            Add-Result -Id "B7" -Title "에이전트 자신의 PID 제외" -Status PASS -Detail ("PID " + $ready.AgentPid + " 의 net/image_load 이벤트 없음")
        }
        else {
            Add-Result -Id "B7" -Title "에이전트 자신의 PID 제외" -Status FAIL -Detail ("자기 PID 이벤트 " + $selfHits.Count + "건")
        }
    }
    else {
        Add-Result -Id "B7" -Title "에이전트 자신의 PID 제외" -Status SKIP -Detail "에이전트 PID 를 읽지 못했습니다."
    }

    # ============================ 2회차: ETW 세션 중지 감지 ============================
    # 새 에이전트를 띄우고, 밖에서 logman 으로 커널 세션을 중지시켜 etw_stopped -> etw_restarted 를 확인한다.
    Write-Log "B8: ETW 세션 중지 감지 시험"
    $agent2 = Start-EdrAgent -Exe $exe -AgentArgs "--dry-run" -Tag "B-dry2"
    $ready2 = Wait-AgentReady -Agent $agent2 -TimeoutSec 30
    if (-not $ready2 -or -not $ready2.TraceName) {
        Add-Result -Id "B8" -Title "ETW 세션 중지 감지와 자동 재시작" -Status FAIL -Detail "2회차 에이전트 시작 또는 세션 이름 확인에 실패했습니다."
        [void](Stop-EdrAgent -Agent $agent2 -Force)
        return
    }

    # 시작 직후 rundown(proc_existing)이 쏟아지는 동안 잠시 기다린 뒤, 외부에서 세션을 중지시킨다.
    Start-Sleep -Seconds 5
    $logman = Resolve-Tool "logman"
    $stopRun = Invoke-Captured -Name "B8-logman-stop" -FilePath $logman -ArgumentList @("stop", $ready2.TraceName, "-ets") -TimeoutSec 30
    if ($stopRun.ExitCode -ne 0) {
        Add-Result -Id "B8" -Title "ETW 세션 중지 감지와 자동 재시작" -Status FAIL -Detail ("logman stop 실패(종료 코드 " + $stopRun.ExitCode + "): " + $stopRun.Text.Trim())
        [void](Stop-EdrAgent -Agent $agent2 -Force)
        return
    }

    # etw_restarted 가 나올 때까지 기다린다 (감독 스레드가 250ms 안에 감지하고 곧바로 재시작).
    $restarted = Wait-Until -TimeoutSec 20 -Condition {
        (Read-SharedLines -Path $agent2.OutFile) | Where-Object { $_ -match '"kind":"etw_restarted"' } | Select-Object -First 1
    }
    $lines2 = Read-SharedLines -Path $agent2.OutFile
    $idxStopped   = -1
    $idxRestarted = -1
    for ($i = 0; $i -lt $lines2.Count; $i++) {
        if ($idxStopped   -lt 0 -and $lines2[$i] -match '"kind":"etw_stopped"')   { $idxStopped = $i }
        if ($idxRestarted -lt 0 -and $lines2[$i] -match '"kind":"etw_restarted"') { $idxRestarted = $i }
    }

    # 재시작 뒤 heartbeat 가 etw_restarts=1, etw_alive=true 를 보고하는지 (heartbeat 주기 10초 + 여유)
    $hbOk = $false
    if ($restarted) {
        $hbOk = Wait-Until -TimeoutSec 30 -Condition {
            @((Read-SharedLines -Path $agent2.OutFile) | Where-Object { $_ -match '"kind":"heartbeat"' -and $_ -match '"etw_restarts":1' -and $_ -match '"etw_alive":true' }).Count -gt 0
        }
    }

    # 재시작한 세션이 실제로 수집을 이어가는지: 새 표식 명령을 실행해 proc_start 가 나오는지 본다.
    $marker2 = New-Marker
    [void](New-HarmlessActivity -Marker $marker2)
    $resumed = Wait-Until -TimeoutSec 20 -Condition {
        @((Read-SharedLines -Path $agent2.OutFile) | Where-Object { $_ -match '"kind":"proc_start"' -and $_ -match $marker2 }).Count -gt 0
    }

    $b8Problems = @()
    if ($idxStopped -lt 0)   { $b8Problems += "etw_stopped 없음" }
    if ($idxRestarted -lt 0) { $b8Problems += "etw_restarted 없음" }
    if ($idxStopped -ge 0 -and $idxRestarted -ge 0 -and $idxStopped -gt $idxRestarted) { $b8Problems += "etw_stopped 가 etw_restarted 보다 늦음" }
    if (-not $hbOk)   { $b8Problems += "재시작 뒤 heartbeat(etw_restarts=1, etw_alive=true) 없음" }
    if (-not $resumed) { $b8Problems += "재시작 뒤 새 프로세스 이벤트가 수집되지 않음" }
    if ($b8Problems.Count -eq 0) {
        Add-Result -Id "B8" -Title "ETW 세션 중지 감지와 자동 재시작" -Status PASS -Detail "etw_stopped -> etw_restarted, heartbeat etw_restarts=1, 수집 재개 확인"
    }
    else {
        Add-Result -Id "B8" -Title "ETW 세션 중지 감지와 자동 재시작" -Status FAIL -Detail ($b8Problems -join "; ")
    }

    # 2회차 에이전트 정리: 정상 종료를 시도하고, 남은 세션은 00_run.ps1 의 finally 에서도 한 번 더 정리된다.
    $how2 = Stop-EdrAgent -Agent $agent2
    Write-Log ("2회차 에이전트 종료 방식: " + $how2)
}
