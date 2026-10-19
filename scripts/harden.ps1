<#
  harden.ps1 - 분석 VM 에서 edr-lite 수집 신뢰도를 높이는 OS 레벨 설정.
  관리자 PowerShell 에서 "스냅샷 찍기 전에" 1회 실행한다.

  핵심 원리:
    - 센서(edr-lite)는 SYSTEM 으로 상시 실행 → 일반 사용자 권한 샘플이 종료/정지 불가
    - 샘플은 별도의 '제한된 사용자'로 실행 → 센서 파일/프로세스에 손대지 못함
    - 서비스 계정 키(.json)와 개인키(.key)는 SYSTEM 전용 ACL → 인포스틸러가 읽어갈 수 없음
  관리자 권한을 획득한 샘플은 이 보호를 우회할 수 있다. 그 경우는 heartbeat/seq
  공백으로 '탐지'하고, 메모리 덤프·PCAP 등 VM 밖 증거로 교차검증하는 것이 전제다.

  사용:
    .\harden.ps1 -EdrDir C:\edr -SampleUser analyst
#>
[CmdletBinding()]
param(
    [string]$EdrDir = "C:\edr",
    [string]$SampleUser = "analyst",
    [string]$ConfigName = "agent.toml",
    [switch]$CreateSampleUser
)
$ErrorActionPreference = "Stop"
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "관리자 권한으로 실행하세요."
    }
}
Assert-Admin

# 1) (선택) 샘플 실행용 제한 계정 생성
if ($CreateSampleUser) {
    if (-not (Get-LocalUser -Name $SampleUser -ErrorAction SilentlyContinue)) {
        $pw = -join ((33..126) | Get-Random -Count 24 | ForEach-Object {[char]$_})
        New-LocalUser -Name $SampleUser -Password (ConvertTo-SecureString $pw -AsPlainText -Force) `
            -PasswordNeverExpires -AccountNeverExpires | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $SampleUser
        Write-Host "[+] 제한 계정 '$SampleUser' 생성 (임시 비밀번호는 아래, 스냅샷 후 폐기)"
        Write-Host "    $pw"
    } else { Write-Host "[=] 계정 '$SampleUser' 이미 존재" }
}

# 2) C:\edr 를 SYSTEM/Administrators 전용으로 잠금 (상속 제거 → 샘플 계정 접근 차단)
Write-Host "[*] $EdrDir ACL 설정"
icacls $EdrDir /inheritance:r | Out-Null
icacls $EdrDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
# 서비스 계정 키(.json)와 개인키(.key)는 SYSTEM 만 (설정에서 wipe_sa_key=true 면 로드 직후 삭제되어 더 안전)
Get-ChildItem $EdrDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.key', '.json' } | ForEach-Object {
    icacls $_.FullName /inheritance:r /grant:r "SYSTEM:F" | Out-Null
    Write-Host "    [lock] $($_.Name) → SYSTEM 전용"
}

# 3) SYSTEM 부팅 시 자동 실행 작업 등록 (평범한 작업 이름)
$taskName = "WindowsTelemetryService"
$exe = Join-Path $EdrDir "edr-lite.exe"
$cfg = Join-Path $EdrDir $ConfigName
if (-not (Test-Path $exe)) { throw "$exe 없음 — 바이너리를 먼저 배치하세요." }
$action  = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$cfg`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "[+] 예약 작업 '$taskName' 등록 (SYSTEM, 부팅 시 실행, 자동 재시작)"

Write-Host ""
Write-Host "다음 순서:"
Write-Host "  1) Start-ScheduledTask -TaskName $taskName   # 센서 기동"
Write-Host "  2) edr-lite --config $cfg --test            # Cloud Logging 전송 확인 (키가 SYSTEM 전용이므로 SYSTEM 권한으로 실행)"
Write-Host "  3) 이 상태에서 VM 스냅샷 (wipe_sa_key=true 로 쓸 때는 키 파일이 스냅샷에 남는지 확인)"
Write-Host "  4) '$SampleUser' 로 로그인/runas 하여 샘플 실행"
Write-Host "  5) 분석 종료 후 스냅샷 복원. 키 유출이 의심되면 서비스 계정 키를 폐기하고 새로 발급"
