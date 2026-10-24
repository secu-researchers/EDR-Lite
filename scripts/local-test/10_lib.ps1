<#
================================================================================
 10_lib.ps1 - 일반 PC 테스트 러너의 공통 도구 모음

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증). 처음 실행할 때 오류가 날 수 있습니다.

 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 `. .\10_lib.ps1` (점 소싱) 으로 불러옵니다.
 점 소싱된 파일의 함수와 `$script:` 변수는 00_run.ps1 과 같은 범위(scope)를 공유하므로, 단계 파일(2x_stage-*.ps1 등)의
 함수도 아래 도구와 `$script:Ctx`, `$script:Results` 를 그대로 쓸 수 있습니다.

 이 파일이 제공하는 것
   1. 실행 컨텍스트와 로그        : Initialize-TestRun, Write-Log
   2. 판정 기록과 요약            : Add-Result, Show-Summary
   3. 환경 확인                   : Test-IsAdmin, Resolve-Tool
   4. 외부 명령 실행              : ConvertTo-ArgString, Invoke-Captured, Stop-ProcessTree
   5. 에이전트(edr-lite) 제어     : Start-EdrAgent, Wait-AgentReady, Send-CtrlC,
                                    Stop-EdrAgent, Stop-AllAgents
   6. 파일 읽기와 대기            : Read-SharedLines, Get-KindCounts, Wait-Until
   7. 사용자 확인                 : Confirm-Action

 인코딩 주의
   이 파일에는 한글이 들어 있으므로 반드시 "UTF-8 (BOM 포함)" 으로 저장해야 합니다.
   Windows PowerShell 5.1 은 BOM 이 없는 UTF-8 스크립트를 시스템 기본 코드 페이지로
   읽어 한글을 깨뜨리고, 그 결과 문자열 따옴표가 어긋나 구문 오류가 날 수 있습니다.
================================================================================
#>


# ==============================================================================
# 1. 실행 컨텍스트와 로그
# ==============================================================================

<#
 Initialize-TestRun
   테스트 한 번의 실행에 필요한 상태를 만든다. 00_run.ps1 이 가장 먼저 한 번 호출한다.

   만드는 것
     $script:Ctx         해시테이블. 단계 파일들이 공유하는 설정과 경로.
     $script:Results     판정 결과 목록(ArrayList). Add-Result 가 채우고 Show-Summary 가 읽는다.
     $script:Agents      이 실행이 시작한 에이전트 프로세스 목록. 종료 시 정리하기 위해 기록한다.
     $script:EtwSessions 이 실행이 만든 ETW 세션 이름 목록. 에이전트가 비정상 종료되어도
                         남은 커널 세션을 마지막에 정리하기 위해 기록한다.
     로그 폴더           %TEMP%\edr-test-<시각>\  (모든 명령의 출력과 요약이 여기에 저장된다)
#>
function Initialize-TestRun {
    param(
        # 저장소 루트 (Cargo.toml 이 있는 폴더)
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        # GCP 프로젝트 ID. 비어 있으면 로컬 단계만 의미가 있다.
        [string]$ProjectId = "",
        # GCP 리전 (C 단계 이후에서 사용)
        [string]$Region = "",
        # 이번 실행의 기본 세션 이름 (C 단계 이후에서 사용)
        [string]$SessionName = "",
        # 이번 실행에서 선택된 단계 목록 (예: P, A, B)
        [string[]]$Stages = @(),
        # true 이면 확인 질문 없이 진행한다 (-Yes 스위치)
        [bool]$AutoYes = $false
    )

    # 로그 폴더 이름에 시각을 넣어 실행마다 다른 폴더를 쓴다.
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logDir = Join-Path $env:TEMP ("edr-test-" + $stamp)
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null

    $script:Ctx = @{
        RepoRoot    = $RepoRoot
        # 릴리스 빌드 산출물 경로 (A3 단계가 만든다)
        Exe         = Join-Path $RepoRoot "target\release\edr-lite.exe"
        LogDir      = $logDir
        LogFile     = Join-Path $logDir "run.log"
        ProjectId   = $ProjectId
        Region      = $Region
        SessionName = $SessionName
        Stages      = $Stages
        AutoYes     = $AutoYes
    }

    $script:Results     = New-Object System.Collections.ArrayList
    $script:Agents      = New-Object System.Collections.ArrayList
    $script:EtwSessions = New-Object System.Collections.ArrayList
}

<#
 Write-Log
   콘솔과 로그 파일(run.log)에 한 줄을 기록한다.
   로그 파일은 UTF-8 로 저장된다. 비밀 값(키, 웹훅 주소, 토큰)은 절대 이 함수에 넘기지 않는다.
#>
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "HH:mm:ss"), $Level, $Message

    # 로그 파일 기록 (초기화 전에 호출되면 파일 기록만 건너뛴다)
    if ($script:Ctx -and $script:Ctx.LogFile) {
        Add-Content -LiteralPath $script:Ctx.LogFile -Value $line -Encoding UTF8
    }

    # 수준별 색상으로 콘솔 출력
    $color = "Gray"
    if ($Level -eq "WARN")  { $color = "Yellow" }
    if ($Level -eq "ERROR") { $color = "Red" }
    Write-Host $line -ForegroundColor $color
}


# ==============================================================================
# 2. 판정 기록과 요약
# ==============================================================================

<#
 Add-Result
   체크리스트 항목 하나의 판정을 기록하고 화면에 한 줄 출력한다.

   Status 의 뜻
     PASS    통과 기준을 만족함
     FAIL    통과 기준을 만족하지 못함 (원인을 Detail 에 적는다)
     SKIP    조건이 맞지 않아 실행하지 않음 (이유를 Detail 에 적는다)
     MANUAL  스크립트가 확인할 수 없어 사람이 확인해야 함 (방법을 Detail 에 적는다)

   Id 는 체크리스트의 항목 번호(P1, A1, B3 ...)를 그대로 쓴다.
#>
function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][ValidateSet("PASS", "FAIL", "SKIP", "MANUAL")][string]$Status,
        [string]$Detail = ""
    )

    # 결과 목록에 추가한다. ArrayList.Add 는 인덱스를 반환하므로 [void] 로 출력을 버린다.
    [void]$script:Results.Add([pscustomobject]@{
        Id     = $Id
        Status = $Status
        Title  = $Title
        Detail = $Detail
    })

    # 상태별 색상
    $color = "White"
    if ($Status -eq "PASS")   { $color = "Green" }
    if ($Status -eq "FAIL")   { $color = "Red" }
    if ($Status -eq "SKIP")   { $color = "Yellow" }
    if ($Status -eq "MANUAL") { $color = "Cyan" }

    $head = "[{0,-6}] {1,-3} {2}" -f $Status, $Id, $Title
    Write-Host $head -ForegroundColor $color
    if ($Detail) {
        Write-Host ("           " + $Detail) -ForegroundColor DarkGray
    }

    # 같은 내용을 로그 파일에도 남긴다.
    if ($script:Ctx -and $script:Ctx.LogFile) {
        Add-Content -LiteralPath $script:Ctx.LogFile -Value $head -Encoding UTF8
        if ($Detail) { Add-Content -LiteralPath $script:Ctx.LogFile -Value ("           " + $Detail) -Encoding UTF8 }
    }
}

<#
 Show-Summary
   모든 판정을 표로 출력하고, 같은 내용을 로그 폴더에 summary.txt 와 results.csv 로 저장한다.
   반환값: FAIL 항목 수 (00_run.ps1 이 종료 코드로 쓴다).
#>
function Show-Summary {
    $all = @($script:Results)
    $pass   = @($all | Where-Object { $_.Status -eq "PASS" }).Count
    $fail   = @($all | Where-Object { $_.Status -eq "FAIL" }).Count
    $skip   = @($all | Where-Object { $_.Status -eq "SKIP" }).Count
    $manual = @($all | Where-Object { $_.Status -eq "MANUAL" }).Count

    Write-Host ""
    Write-Host "================ 결과 요약 ================" -ForegroundColor White
    if ($all.Count -gt 0) {
        # -Wrap 으로 긴 Detail 이 잘리지 않게 하고, 넓은 폭으로 문자열화해 파일에도 저장한다.
        $table = $all | Format-Table Id, Status, Title, Detail -AutoSize -Wrap | Out-String -Width 220
        Write-Host $table
        Set-Content -LiteralPath (Join-Path $script:Ctx.LogDir "summary.txt") -Value $table -Encoding UTF8
        $all | Export-Csv -LiteralPath (Join-Path $script:Ctx.LogDir "results.csv") -NoTypeInformation -Encoding UTF8
    }
    Write-Host ("PASS {0}  FAIL {1}  SKIP {2}  MANUAL {3}" -f $pass, $fail, $skip, $manual) -ForegroundColor White
    Write-Host ("로그 폴더: " + $script:Ctx.LogDir) -ForegroundColor White
    return $fail
}


# ==============================================================================
# 3. 환경 확인
# ==============================================================================

<#
 Test-IsAdmin
   현재 PowerShell 이 관리자 권한인지 확인한다.
   ETW 커널 세션은 관리자 권한이 있어야 시작되므로 B 단계에서 필요하다.
#>
function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
 Resolve-Tool
   명령 이름으로 실행 파일의 전체 경로를 찾는다. 못 찾으면 $null.

   .exe, .cmd, .bat 순서로 찾는 이유
     Windows PowerShell 에서 `gcloud` 라고 쓰면 같은 폴더의 gcloud.ps1 이 먼저 잡혀
     실행 정책 때문에 막히는 일이 있다. 그래서 확장자를 붙여 .cmd 를 직접 찾는다.
     -CommandType Application 은 cmdlet, 별칭, .ps1 스크립트를 제외하고 실제 실행 파일만
     대상으로 한다 (예: `curl` 별칭이 아니라 curl.exe 를 찾기 위함).
#>
function Resolve-Tool {
    param([Parameter(Mandatory = $true)][string]$Name)
    foreach ($candidate in @(($Name + ".exe"), ($Name + ".cmd"), ($Name + ".bat"), $Name)) {
        $cmd = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}


# ==============================================================================
# 4. 외부 명령 실행
# ==============================================================================

<#
 ConvertTo-ArgString
   인자 배열을 Windows 명령줄 한 줄로 합친다. 공백이나 따옴표가 든 인자는 따옴표로 감싼다.
   System.Diagnostics.ProcessStartInfo.Arguments 는 배열이 아니라 한 줄 문자열만 받기 때문에
   (Windows PowerShell 5.1 의 .NET Framework 에는 ArgumentList 컬렉션이 없다) 직접 만든다.

   규칙 (CommandLineToArgvW 호환)
     - 인자 안의 따옴표(")는 \" 로 바꾼다. 이때 따옴표 바로 앞의 역슬래시는 두 배로 한다.
     - 닫는 따옴표 직전에 오는 역슬래시도 두 배로 한다 (닫는 따옴표가 이스케이프되는 것을 막음).
#>
function ConvertTo-ArgString {
    param([string[]]$Items = @())
    $parts = foreach ($a in $Items) {
        if ($null -eq $a) { continue }
        if ($a -eq "") { '""'; continue }
        if ($a -match '[\s"]') {
            $s = $a -replace '(\\*)"', '$1$1\"'   # 따옴표 앞 역슬래시를 두 배로 하고 따옴표를 이스케이프
            $s = $s -replace '(\\+)$', '$1$1'     # 끝의 역슬래시를 두 배로
            '"' + $s + '"'
        }
        else {
            $a
        }
    }
    return ($parts -join " ")
}

<#
 Stop-ProcessTree
   프로세스와 그 자손을 모두 강제 종료한다 (taskkill /T /F).
   cmd.exe 로 감싸 시작한 에이전트처럼 부모-자식 구조일 때 자식까지 정리하기 위해 필요하다.
   이미 끝난 프로세스라도 오류 없이 지나간다.
#>
function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        # Start-Process 로 숨김 창에서 실행한다. (네이티브 명령의 stderr 를 리다이렉트하면
        # Windows PowerShell 5.1 이 오류 레코드로 바꿔 스크립트를 중단시킬 수 있어서 피한다.)
        Start-Process -FilePath "taskkill.exe" -ArgumentList @("/PID", "$ProcessId", "/T", "/F") -WindowStyle Hidden -Wait
    }
    catch {
        Write-Log ("프로세스 트리 종료 실패 (PID " + $ProcessId + "): " + $_.Exception.Message) "WARN"
    }
}

<#
 Invoke-Captured
   외부 명령을 실행하고 표준 출력과 표준 오류를 모두 캡처한다. 화면에는 출력하지 않고,
   로그 폴더에 <Name>.out.txt 와 <Name>.err.txt 로 저장한다.

   왜 `& 명령 2>&1` 대신 Process 를 직접 쓰는가
     Windows PowerShell 5.1 은 네이티브 명령의 stderr 를 리다이렉트하면 각 줄을
     오류 레코드로 바꿔 `$ErrorActionPreference = "Stop"` 환경에서 스크립트를 중단시킨다.
     cargo, python 처럼 진행 상황을 stderr 로 출력하는 명령에서 문제가 되므로
     System.Diagnostics.Process 로 두 스트림을 안전하게 읽는다.

   반환 객체
     ExitCode  종료 코드 (시간 초과로 강제 종료한 경우 -1)
     StdOut    표준 출력 전체
     StdErr    표준 오류 전체
     TimedOut  시간 초과 여부
     Text      StdOut 과 StdErr 를 합친 문자열 (결과 문구를 정규식으로 찾을 때 편리)
#>
function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = "",
        [int]$TimeoutSec = 600
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = ConvertTo-ArgString $ArgumentList
    $psi.UseShellExecute        = $false   # 리다이렉트하려면 false 여야 한다
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true    # 콘솔 창을 띄우지 않는다
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8
    # python 이 파이프로 출력할 때 한글 코드 페이지(cp949) 대신 UTF-8 을 쓰도록 한다.
    $psi.EnvironmentVariables["PYTHONUTF8"] = "1"
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    # 두 스트림을 비동기로 읽는다. 한쪽 버퍼가 가득 차 자식이 멈추는 교착을 막기 위해서다.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $timedOut = $false
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        Stop-ProcessTree -ProcessId $proc.Id
        [void]$proc.WaitForExit(5000)
    }

    $stdout = $outTask.Result
    $stderr = $errTask.Result
    $exit = -1
    if (-not $timedOut) { $exit = $proc.ExitCode }

    # BOM 없는 UTF-8 로 저장한다.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $script:Ctx.LogDir ($Name + ".out.txt")), $stdout, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $script:Ctx.LogDir ($Name + ".err.txt")), $stderr, $utf8)

    return [pscustomobject]@{
        ExitCode = $exit
        StdOut   = $stdout
        StdErr   = $stderr
        TimedOut = $timedOut
        Text     = ($stdout + "`n" + $stderr)
    }
}


# ==============================================================================
# 5. 에이전트(edr-lite) 제어
# ==============================================================================

<#
 Start-EdrAgent
   edr-lite.exe 를 백그라운드로 시작하고, 표준 출력과 표준 오류를 파일로 저장한다.

   왜 cmd.exe /c 로 감싸는가
     PowerShell 5.1 의 `>` 는 파일을 UTF-16 으로 저장해 크기 추정이 두 배가 된다.
     cmd.exe 의 `>` 는 에이전트가 쓴 UTF-8 바이트를 그대로 저장한다.

   왜 CreateNoWindow 인가
     자식 프로세스가 이 PowerShell 창의 콘솔을 공유하면 Ctrl+C 를 보낼 때 PowerShell 도
     함께 중단된다. CreateNoWindow 로 시작하면 자식이 자기만의 (숨겨진) 콘솔을 갖게 되어
     그 콘솔에만 Ctrl+C 신호를 보낼 수 있다.

   인자
     Exe        에이전트 실행 파일 전체 경로
     AgentArgs  에이전트에 줄 인자 문자열 (예: --dry-run 또는 --config "C:\edr\agent.toml")
     Tag        출력 파일 이름에 쓸 이름 (예: dry1 -> dry1.ndjson, dry1.err.txt)

   반환 객체: Process(실제로는 cmd.exe), OutFile, ErrFile, Tag, StartedAt
#>
function Start-EdrAgent {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string]$AgentArgs,
        [Parameter(Mandatory = $true)][string]$Tag
    )

    $outFile = Join-Path $script:Ctx.LogDir ($Tag + ".ndjson")
    $errFile = Join-Path $script:Ctx.LogDir ($Tag + ".err.txt")

    # cmd /c "<따옴표 친 전체 명령>" 형태. 바깥 따옴표 한 쌍은 cmd 가 벗겨낸다.
    $inner = '"{0}" {1} > "{2}" 2> "{3}"' -f $Exe, $AgentArgs, $outFile, $errFile

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName         = $env:ComSpec
    $psi.Arguments        = '/c "' + $inner + '"'
    $psi.UseShellExecute  = $false
    $psi.CreateNoWindow   = $true
    $psi.WorkingDirectory = $script:Ctx.RepoRoot

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    $agent = [pscustomobject]@{
        Process   = $proc
        OutFile   = $outFile
        ErrFile   = $errFile
        Tag       = $Tag
        StartedAt = Get-Date
    }
    # 종료 시 정리할 수 있도록 목록에 기록한다.
    [void]$script:Agents.Add($agent)
    return $agent
}

<#
 Wait-AgentReady
   에이전트가 "수집 시작" 메시지를 stderr 에 출력할 때까지 기다린 뒤, 그 출력에서
   ETW 세션 이름과 에이전트 PID 를 읽어 반환한다. 시간 안에 준비되지 않으면 $null.

   에이전트가 stderr 로 출력하는 문구 (src/main.rs, src/etw.rs 기준)
     [edr] ETW 세션: WinTelemetry-xxxx-1234
     [edr] 수집 시작 (session=dry-run, pid=1234). Ctrl+C 로 종료
#>
function Wait-AgentReady {
    param(
        [Parameter(Mandatory = $true)]$Agent,
        [int]$TimeoutSec = 30
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        # 에이전트가 이미 끝났다면 더 기다릴 필요가 없다.
        if ($Agent.Process.HasExited) { return $null }

        $errText = (Read-SharedLines -Path $Agent.ErrFile) -join "`n"
        if ($errText -match "수집 시작") {
            $traceName = ""
            $agentPid  = 0
            if ($errText -match "ETW 세션:\s*(\S+)") { $traceName = $Matches[1] }
            if ($errText -match "pid=(\d+)")        { $agentPid  = [int]$Matches[1] }
            # 나중에 정리할 수 있도록 세션 이름을 기록한다.
            if ($traceName) { [void]$script:EtwSessions.Add($traceName) }
            return [pscustomobject]@{ TraceName = $traceName; AgentPid = $agentPid }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

<#
 Send-CtrlC
   숨겨진 콘솔에서 실행 중인 프로세스에 Ctrl+C 신호를 보낸다. 성공하면 0 을 반환한다.

   원리
     GenerateConsoleCtrlEvent 는 "자기가 붙어 있는 콘솔"에만 신호를 보낼 수 있다.
     그래서 신호를 보내는 쪽이 FreeConsole 로 자기 콘솔을 놓고 AttachConsole(대상 PID) 로
     대상의 콘솔에 붙은 뒤 신호를 발생시킨다. 이 과정에서 신호를 보내는 프로세스 자신도
     Ctrl+C 를 받으므로 SetConsoleCtrlHandler(NULL, TRUE) 로 자신은 무시하게 한다.

   왜 별도 PowerShell 프로세스로 하는가
     이 스크립트가 직접 FreeConsole/AttachConsole 을 하면 화면 출력이 깨지거나 스크립트가
     중단될 수 있다. 일회용 도우미 프로세스에서 하면 이 스크립트의 콘솔은 영향을 받지 않는다.

   반환값 (도우미 종료 코드)
     0 신호 발생 성공 / 2 대상 콘솔에 붙지 못함 / 3 신호 발생 실패 / 그 밖 값은 도우미 자체 오류
#>
function Send-CtrlC {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $helperPath = Join-Path $script:Ctx.LogDir "send-ctrlc.ps1"
    if (-not (Test-Path -LiteralPath $helperPath)) {
        # 도우미 스크립트. 작은따옴표 here-string 이라 내용이 그대로(변수 확장 없이) 저장된다.
        $helper = @'
param([int]$TargetPid)
# kernel32 의 콘솔 API 를 .NET 형식으로 선언한다.
Add-Type -Namespace EdrTest -Name Native -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole();
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint dwProcessId);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleCtrlHandler(IntPtr HandlerRoutine, bool Add);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
"@
# 1) 내 콘솔을 놓고 2) 대상의 콘솔에 붙는다.
[void][EdrTest.Native]::FreeConsole()
if (-not [EdrTest.Native]::AttachConsole([uint32]$TargetPid)) { exit 2 }
# 3) 내가 받을 Ctrl+C 는 무시한다.
[void][EdrTest.Native]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)
# 4) CTRL_C_EVENT(0) 를 현재 콘솔의 모든 프로세스 그룹에 보낸다.
$ok = [EdrTest.Native]::GenerateConsoleCtrlEvent(0, 0)
Start-Sleep -Milliseconds 500
[void][EdrTest.Native]::FreeConsole()
if ($ok) { exit 0 } else { exit 3 }
'@
        Set-Content -LiteralPath $helperPath -Value $helper -Encoding UTF8
    }

    $powershell = Resolve-Tool "powershell"
    if (-not $powershell) { return 99 }

    $r = Invoke-Captured -Name ("ctrlc-" + $ProcessId) -FilePath $powershell `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $helperPath, "-TargetPid", "$ProcessId") `
        -TimeoutSec 30
    return $r.ExitCode
}

<#
 Stop-EdrAgent
   에이전트를 종료하고, 어떻게 끝났는지를 문자열로 반환한다.

   기본 동작(정상 종료 시도)
     1) Send-CtrlC 로 Ctrl+C 를 보낸다. 에이전트는 Ctrl+C 를 받으면 agent_stop 이벤트를
        내고 ETW 세션을 정리한 뒤 최대 10초 안에 종료한다.
     2) 최대 25초 기다린다.
     3) 신호를 보내지 못했거나 시간 안에 끝나지 않으면 프로세스 트리를 강제 종료한다.

   -Force 를 주면 신호 없이 바로 강제 종료한다 (agent_stop 이 기록되지 않는다).

   반환값
     already-exited  이미 끝나 있었음
     graceful        Ctrl+C 로 정상 종료됨
     ctrlc-failed    Ctrl+C 신호를 보내지 못해 강제 종료함 (정상 종료 여부는 판단 불가)
     ctrlc-timeout   신호는 보냈지만 시간 안에 끝나지 않아 강제 종료함 (에이전트 종료 처리 문제 가능)
     killed          -Force 로 강제 종료함
#>
function Stop-EdrAgent {
    param(
        [Parameter(Mandatory = $true)]$Agent,
        [switch]$Force
    )
    if ($Agent.Process.HasExited) { return "already-exited" }

    if (-not $Force) {
        $sig = Send-CtrlC -ProcessId $Agent.Process.Id
        if ($sig -eq 0) {
            if ($Agent.Process.WaitForExit(25000)) { return "graceful" }
            Stop-ProcessTree -ProcessId $Agent.Process.Id
            return "ctrlc-timeout"
        }
        Stop-ProcessTree -ProcessId $Agent.Process.Id
        return "ctrlc-failed"
    }

    Stop-ProcessTree -ProcessId $Agent.Process.Id
    return "killed"
}

<#
 Stop-AllAgents
   이 실행이 시작한 모든 에이전트를 강제 종료하고, 이 실행이 만든 ETW 커널 세션을 지운다.
   에이전트가 강제 종료되면 커널 세션이 남을 수 있으므로 00_run.ps1 의 finally 에서 반드시 호출한다.
   세션이 이미 없으면 logman 이 오류를 내지만 결과를 무시한다.
#>
function Stop-AllAgents {
    foreach ($a in $script:Agents) {
        if (-not $a.Process.HasExited) { Stop-ProcessTree -ProcessId $a.Process.Id }
    }
    foreach ($name in $script:EtwSessions) {
        try {
            Start-Process -FilePath "logman.exe" -ArgumentList @("stop", $name, "-ets") -WindowStyle Hidden -Wait
        }
        catch {
            Write-Log ("ETW 세션 정리 실패 (" + $name + "): " + $_.Exception.Message) "WARN"
        }
    }
}


# ==============================================================================
# 6. 파일 읽기와 대기
# ==============================================================================

<#
 Read-SharedLines
   다른 프로세스가 쓰는 중인 텍스트 파일을 UTF-8 로 읽어 줄 배열로 돌려준다.
   FileShare.ReadWrite 로 열기 때문에 에이전트가 파일을 열어 둔 상태에서도 읽을 수 있다.
   파일이 없거나 비어 있으면 빈 배열을 반환한다. 마지막 줄은 쓰는 도중이라 잘려 있을 수 있다.
#>
function Read-SharedLines {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                                 [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
    }
    finally {
        $fs.Dispose()
    }
    if ([string]::IsNullOrEmpty($text)) { return @() }
    return @($text -split "`r?`n" | Where-Object { $_ -ne "" })
}

<#
 Get-KindCounts
   NDJSON 줄 배열에서 이벤트 종류(kind)별 개수를 센다. 해시테이블(종류 -> 개수)을 반환한다.

   각 줄은 {"v":1,"sid":"...","seq":N,"ts_ms":N,"kind":"종류",...} 형태이므로,
   줄에서 처음 나오는 "kind":"..." 가 이벤트 종류이다 (이후 필드에 같은 글자가 있어도 무시).
   ConvertFrom-Json 을 줄마다 쓰면 수만 줄에서 매우 느려 정규식으로 처리한다.
#>
function Get-KindCounts {
    param([string[]]$Lines = @())
    $counts = @{}
    $regex = New-Object System.Text.RegularExpressions.Regex('"kind":"([a-z_]+)"')
    foreach ($line in $Lines) {
        $m = $regex.Match($line)
        if ($m.Success) {
            $k = $m.Groups[1].Value
            if ($counts.ContainsKey($k)) { $counts[$k] = $counts[$k] + 1 } else { $counts[$k] = 1 }
        }
    }
    return $counts
}

<#
 Wait-Until
   조건 스크립트블록이 $true 를 반환할 때까지 주기적으로 확인한다.
   시간 안에 만족하면 $true, 시간이 지나면 $false.
   조건 블록은 호출한 쪽의 변수를 그대로 볼 수 있다 (PowerShell 의 동적 범위).
   이 함수 안의 변수 이름이 호출 쪽 변수와 겹치지 않도록 앞에 __ 를 붙였다.
#>
function Wait-Until {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [int]$TimeoutSec = 30,
        [int]$IntervalMs = 500
    )
    $__deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds $IntervalMs
    } while ((Get-Date) -lt $__deadline)
    return $false
}


# ==============================================================================
# 7. 사용자 확인
# ==============================================================================

<#
 Confirm-Action
   비용이 들거나 GCP 설정을 바꾸는 단계 앞에서 사용자에게 확인을 받는다.
   -Yes 로 실행했으면 묻지 않고 $true. 그렇지 않으면 "yes" 를 정확히 입력해야 $true 이다.
   (Enter 만 누르거나 다른 글자를 입력하면 $false)
#>
function Confirm-Action {
    param([Parameter(Mandatory = $true)][string]$Message)
    if ($script:Ctx.AutoYes) {
        Write-Log ("자동 승인(-Yes): " + $Message) "WARN"
        return $true
    }
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    $answer = Read-Host "계속하려면 yes 를 입력하세요"
    return ($answer -eq "yes")
}


# ==============================================================================
# 8. 대화형 입력, GCP 호출, 파일 도구 (전체 단계 실행용)
#    15_prompts.ps1 과 30번 이후 단계 파일(C~F)이 쓰는 도구들이다.
# ==============================================================================

<#
 Read-WithDefault
   질문을 보여 주고 한 줄을 입력받는다. 그냥 Enter 를 누르면 기본값을 돌려준다.
   기본값이 있으면 질문 끝에 [기본값: ...] 으로 표시한다.
#>
function Read-WithDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [string]$Default = ""
    )
    $suffix = ""
    if ($Default -ne "") { $suffix = " [기본값: " + $Default + "]" }
    $value = Read-Host ($Prompt + $suffix)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
}

<#
 Read-SecretSecure
   입력이 화면에 표시되지 않는 한 줄 입력을 SecureString 으로 받는다 (웹훅 주소 같은 비밀 값용).
   아무것도 입력하지 않으면 $null 을 돌려준다.
#>
function Read-SecretSecure {
    param([Parameter(Mandatory = $true)][string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    if ($secure.Length -eq 0) { return $null }
    return $secure
}

<#
 ConvertFrom-SecureText
   SecureString 을 평문 문자열로 바꾼다. 평문이 메모리에 남는 시간을 줄이려면 호출한 쪽에서
   사용 직후 변수에 $null 을 대입한다. 로그나 화면에는 절대 출력하지 않는다.
#>
function ConvertFrom-SecureText {
    param([Parameter(Mandatory = $true)][System.Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

<#
 Confirm-Manual
   스크립트가 직접 확인할 수 없는 항목(예: Discord 에 경보가 도착했는지)을 사람에게 묻는다.
   반환값: "y"(그렇다) / "n"(아니다) / "skip"(Enter 또는 -Yes 실행으로 건너뜀)
#>
function Confirm-Manual {
    param([Parameter(Mandatory = $true)][string]$Question)
    if ($script:Ctx.AutoYes) { return "skip" }
    $answer = Read-Host ($Question + " (y=예 / n=아니오 / Enter=건너뜀)")
    switch ($answer.Trim().ToLower()) {
        "y"     { return "y" }
        "n"     { return "n" }
        default { return "skip" }
    }
}

<#
 Invoke-Interactive
   출력을 캡처하지 않고 이 콘솔에 그대로 연결해 실행한다. 브라우저 로그인(gcloud auth login)처럼
   사람이 상호작용해야 하는 명령용이다. 종료 코드를 반환한다.
#>
function Invoke-Interactive {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = ""
    )
    $sp = @{ FilePath = $FilePath; Wait = $true; PassThru = $true; NoNewWindow = $true }
    $argString = ConvertTo-ArgString $ArgumentList
    if ($argString -ne "") { $sp.ArgumentList = $argString }
    if ($WorkingDirectory -ne "") { $sp.WorkingDirectory = $WorkingDirectory }
    $proc = Start-Process @sp
    return $proc.ExitCode
}

<#
 Invoke-Gcloud
   gcloud 를 실행하고 출력을 캡처한다 (Invoke-Captured 와 같은 반환 객체).
   - gcloud.cmd 를 직접 호출하므로 PowerShell 실행 정책에 막히지 않는다.
   - 프로젝트가 정해져 있으면 --project=<ID> 를 자동으로 붙인다 (-NoProject 로 끌 수 있음).
#>
function Invoke-Gcloud {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSec = 300,
        [switch]$NoProject
    )
    $gcloud = Resolve-Tool "gcloud"
    if (-not $gcloud) { throw "gcloud 를 찾을 수 없습니다." }
    $argsAll = @($ArgumentList)
    if ((-not $NoProject) -and $script:Ctx.ProjectId) { $argsAll += ("--project=" + $script:Ctx.ProjectId) }
    return Invoke-Captured -Name $Name -FilePath $gcloud -ArgumentList $argsAll -TimeoutSec $TimeoutSec
}

<#
 Get-BqTable
   SQL 에 넣을 BigQuery 테이블 이름을 만든다. 프로젝트 ID 에 하이픈이 있어 백틱(`)으로 감싸야 한다.
   PowerShell 에서 백틱은 이스케이프 문자라 문자열에 직접 쓸 수 없으므로 문자 코드(96)로 만든다.
   Name: events 또는 alerts
#>
function Get-BqTable {
    param([Parameter(Mandatory = $true)][ValidateSet("events", "alerts")][string]$Name)
    $tick = [string][char]96
    return ($tick + $script:Ctx.ProjectId + ".edr_logs." + $Name + $tick)
}

<#
 Invoke-BqQuery
   bq 로 표준 SQL 을 실행하고 결과 행을 객체 배열로 돌려준다. 실패하면 예외를 던진다.
   주의: 이 도구는 인자를 명령줄로 넘기므로 SQL 안에 큰따옴표(")를 쓰지 않는다 (문자열은 작은따옴표).
   결과 값은 bq 의 JSON 출력 특성상 모두 문자열이다 (숫자도 "12" 처럼 문자열).
#>
function Invoke-BqQuery {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Sql,
        [int]$TimeoutSec = 180
    )
    $bq = Resolve-Tool "bq"
    if (-not $bq) { throw "bq 를 찾을 수 없습니다." }
    $argsAll = @("query", "--use_legacy_sql=false", "--format=json", "--quiet", ("--project_id=" + $script:Ctx.ProjectId))
    if ($script:Ctx.BqLocation) { $argsAll += ("--location=" + $script:Ctx.BqLocation) }
    $argsAll += $Sql
    $r = Invoke-Captured -Name $Name -FilePath $bq -ArgumentList $argsAll -TimeoutSec $TimeoutSec
    if ($r.ExitCode -ne 0) { throw ("bq query 실패 (" + $Name + "): " + $r.StdErr.Trim()) }
    $text = $r.StdOut.Trim()
    if ($text -eq "") { return @() }
    $parsed = $text | ConvertFrom-Json
    if ($null -eq $parsed) { return @() }
    return @($parsed)
}

<#
 Wait-BqRows
   조건이 만족될 때까지 같은 SQL 을 주기적으로 다시 실행한다 (스트리밍 적재와 Function 처리에는 지연이 있다).
   Condition 은 결과 행 배열을 인자로 받아 $true/$false 를 돌려주는 스크립트블록이다.
     예) { param($rows) @($rows).Count -ge 2 }
   반환: 조건을 만족한 시점의 행 배열. 시간 안에 만족하지 못하면 $null.
   조회 오류는 로그에 남기고 계속 재시도한다 (일시적인 BigQuery 지연일 수 있음).
#>
function Wait-BqRows {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [int]$TimeoutSec = 180,
        [int]$IntervalSec = 15
    )
    $__deadline = (Get-Date).AddSeconds($TimeoutSec)
    $__rows = @()
    do {
        try {
            $__rows = Invoke-BqQuery -Name $Name -Sql $Sql
        }
        catch {
            Write-Log ("BigQuery 조회 오류(재시도): " + $_.Exception.Message) "WARN"
        }
        if (& $Condition $__rows) { return ,$__rows }   # 앞의 쉼표는 빈 배열이 풀려 사라지는 것을 막는다
        Start-Sleep -Seconds $IntervalSec
    } while ((Get-Date) -lt $__deadline)
    return $null
}

<#
 Get-KeyInfo
   서비스 계정 키 파일에서 "비밀이 아닌" 식별 정보만 읽어 돌려준다 (Type, ProjectId, ClientEmail, KeyId).
   개인키(private_key)는 읽은 직후 폐기하며 반환하거나 출력하지 않는다.
   파일이 없거나 JSON 이 아니면 $null.
#>
function Get-KeyInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        return $null
    }
    if ($null -eq $obj) { return $null }
    $info = [pscustomobject]@{
        Type        = $obj.type
        ProjectId   = $obj.project_id
        ClientEmail = $obj.client_email
        KeyId       = $obj.private_key_id
    }
    $obj = $null
    return $info
}

<#
 Write-TextFile
   텍스트를 BOM 없는 UTF-8 로 저장한다 (폴더가 없으면 만든다).
   에이전트 설정(agent.toml)처럼 BOM 이 있으면 파서가 거부할 수 있는 파일에 쓴다.
#>
function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

<#
 New-AgentConfigText
   에이전트 설정 파일(agent.toml)의 내용을 만든다 (agent.example.toml 과 같은 키 이름).
   윈도우 경로의 역슬래시는 TOML 작은따옴표 문자열(이스케이프 없음)로 쓴다.
#>
function New-AgentConfigText {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectId,
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [bool]$ImageLoads = $false,
        [int]$HeartbeatSecs = 10
    )
    $img = "false"
    if ($ImageLoads) { $img = "true" }
    $lines = @(
        ('gcp_project_id = "{0}"' -f $ProjectId),
        ("sa_key_path = '{0}'" -f $KeyPath),
        ('session_id = "{0}"' -f $SessionId),
        ("collect_image_loads = {0}" -f $img),
        ("heartbeat_secs = {0}" -f $HeartbeatSecs)
    )
    return (($lines -join "`r`n") + "`r`n")
}

<#
 Test-ScriptSyntax
   PowerShell 스크립트를 실행하지 않고 구문만 검사한다. 오류가 없으면 빈 배열,
   있으면 "줄:열 메시지" 문자열 배열을 돌려준다.
#>
function Test-ScriptSyntax {
    param([Parameter(Mandatory = $true)][string]$Path)
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($null -eq $errors -or $errors.Count -eq 0) { return @() }
    return @($errors | ForEach-Object { "{0}:{1} {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message })
}
