<#
================================================================================
 50_stage-cleanup.ps1 - 체크리스트 F(정리) 단계

 [상태] 작성자가 실행해 보지 않은 코드입니다(미검증).

 이 파일은 직접 실행하지 않습니다. 00_run.ps1 이 점 소싱으로 불러오며 Invoke-StageF 를 호출합니다.
 F 단계는 두 곳에서 호출됩니다.
   1) 정상 흐름: P~F 를 모두 고르면 마지막 단계로 실행됩니다.
   2) 안전망: C~E 중 어디서 멈추거나 실패하거나 Ctrl+C 로 중단해도, GCP 를 건드렸다면
      00_run.ps1 의 finally 가 이 함수를 한 번 호출합니다. 그래서 이 함수는
      "이번 실행이 실제로 한 일만" 되돌리도록, 어느 단계까지 갔는지 몰라도 안전해야 합니다.

   F1  에이전트, 방화벽 규칙 정리
   F2  이번 실행이 발급한 서비스 계정 키 폐기와 파일 삭제, 이번 실행이 만든 agent.toml 되돌리기
   F3  Pub/Sub 디버그 구독 삭제 (있다면)
   F4  _Default 로그 싱크 다시 끄기 (이번 실행이 켰다면)
   F5  테스트 데이터 정리 (기본은 삭제하지 않음, 삭제하려면 프로젝트 ID 를 직접 입력)
   F6  임시 파일 안내

 되돌리는 대상은 $script:Ctx 에 기록된 값으로만 정합니다 (C, D 단계가 기록).
   KeyCreated, KeyId       이번 실행이 만든 키만 폐기합니다. 기존 키를 재사용했다면 건드리지 않습니다.
   DefaultSinkEnabled      이번 실행이 켠 _Default 싱크만 다시 끕니다.
   ConfigWritten, ConfigBackup  이번 실행이 만든 agent.toml 만 지우고, 옮겨 둔 원본이 있으면 되돌립니다.
   FirewallRules           남아 있는 이번 실행의 방화벽 규칙을 지웁니다.

 프로젝트 삭제는 이 스크립트가 하지 않습니다 (되돌릴 수 없으므로 콘솔에서 직접).
================================================================================
#>


function Invoke-StageF {
    $ctx = $script:Ctx
    $project = $ctx.ProjectId
    $region = $ctx.Region
    $gcpDir = Join-Path $ctx.RepoRoot "gcp"
    $revokePs1 = Join-Path $gcpDir "revoke-key.ps1"
    $powershell = Resolve-Tool "powershell"
    $haveGcp = ($project -ne "" -and (Resolve-Tool "gcloud"))

    # ---- F1 에이전트와 방화벽 규칙 정리 -------------------------------------------------
    # 이 실행이 시작한 에이전트를 PID 로 종료하고 ETW 세션을 지운다 (이름으로 일괄 종료하지 않는다).
    try {
        Stop-AllAgents
        $left = @()
        # 이번 실행이 기록한 규칙 + 체크리스트가 쓰는 고정 이름(edr-test-block)이 남아 있으면 지운다.
        $names = @("edr-test-block")
        if ($ctx.FirewallRules) { $names += @($ctx.FirewallRules) }
        foreach ($n in ($names | Select-Object -Unique)) {
            if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) {
                Remove-NetFirewallRule -DisplayName $n -ErrorAction Stop
                $left += $n
            }
        }
        $ctx.FirewallRules = @()
        $detail = "이 실행이 시작한 에이전트와 ETW 세션 정리"
        if ($left.Count -gt 0) { $detail += "; 남아 있던 방화벽 규칙 삭제: " + ($left -join ", ") }
        Add-Result -Id "F1" -Title "에이전트와 방화벽 규칙 정리" -Status PASS -Detail $detail
    }
    catch {
        Add-Result -Id "F1" -Title "에이전트와 방화벽 규칙 정리" -Status FAIL -Detail $_.Exception.Message
    }

    # ---- F2 서비스 계정 키 폐기와 파일 삭제 ---------------------------------------------------
    # 가장 먼저 키를 폐기한다: 키가 살아 있는 동안이 유출 위험이 있는 시간이다.
    try {
        if ($ctx.KeyCreated -ne $true -or [string]::IsNullOrEmpty($ctx.KeyId)) {
            Add-Result -Id "F2" -Title "서비스 계정 키 폐기와 파일 삭제" -Status SKIP -Detail "이 실행이 새로 발급한 키가 없어 건드리지 않습니다."
        }
        elseif (-not $haveGcp -or -not $powershell) {
            Add-Result -Id "F2" -Title "서비스 계정 키 폐기와 파일 삭제" -Status FAIL `
                -Detail "gcloud 또는 powershell 을 찾을 수 없어 키를 폐기하지 못했습니다. revoke-key.ps1 -Action Revoke 로 직접 폐기하세요."
        }
        else {
            $rv = Invoke-Captured -Name "F2-revoke" -FilePath $powershell -TimeoutSec 180 -ArgumentList @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $revokePs1,
                "-ProjectId", $project, "-Action", "Revoke", "-KeyId", $ctx.KeyId)
            # 폐기 결과를 목록으로 다시 확인한다 (목록에 키 ID 가 없어야 한다).
            $ls = Invoke-Captured -Name "F2-list" -FilePath $powershell -TimeoutSec 180 -ArgumentList @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $revokePs1,
                "-ProjectId", $project, "-Action", "List")
            $gone = ($ls.ExitCode -eq 0 -and $ls.Text -notmatch [regex]::Escape($ctx.KeyId))
            # 키 파일 삭제: 폐기에 실패했어도 디스크의 사본은 지운다.
            $fileGone = $true
            if (Test-Path -LiteralPath $ctx.KeyPath) {
                Remove-Item -LiteralPath $ctx.KeyPath -Force -ErrorAction SilentlyContinue
                $fileGone = -not (Test-Path -LiteralPath $ctx.KeyPath)
            }
            if ($rv.ExitCode -eq 0 -and $gone -and $fileGone) {
                $ctx.KeyCreated = $false
                Add-Result -Id "F2" -Title "서비스 계정 키 폐기와 파일 삭제" -Status PASS -Detail "키 폐기 확인(목록에서 사라짐), 키 파일 삭제"
            }
            else {
                Add-Result -Id "F2" -Title "서비스 계정 키 폐기와 파일 삭제" -Status FAIL `
                    -Detail ("폐기 종료 코드 " + $rv.ExitCode + ", 목록에서 사라짐=" + $gone + ", 파일 삭제=" + $fileGone +
                             " | 남아 있으면 revoke-key.ps1 -Action List/Revoke 로 직접 폐기하세요.")
            }
        }
    }
    catch {
        Add-Result -Id "F2" -Title "서비스 계정 키 폐기와 파일 삭제" -Status FAIL -Detail $_.Exception.Message
    }

    # 이번 실행이 만든 agent.toml 을 지우고, 옮겨 둔 원본이 있으면 되돌린다.
    try {
        if ($ctx.ConfigWritten -eq $true -and $ctx.ConfigPath -and (Test-Path -LiteralPath $ctx.ConfigPath)) {
            Remove-Item -LiteralPath $ctx.ConfigPath -Force
        }
        if ($ctx.ConfigBackup -and (Test-Path -LiteralPath $ctx.ConfigBackup)) {
            Move-Item -LiteralPath $ctx.ConfigBackup -Destination $ctx.ConfigPath -Force
            Write-Log ("이전 설정 파일을 되돌렸습니다: " + $ctx.ConfigPath)
        }
        $ctx.ConfigWritten = $false
        $ctx.ConfigBackup = ""
    }
    catch {
        Write-Log ("설정 파일 되돌리기 실패: " + $_.Exception.Message) "WARN"
    }

    # ---- F3 Pub/Sub 디버그 구독 삭제 ------------------------------------------------------
    try {
        if (-not $haveGcp) {
            Add-Result -Id "F3" -Title "디버그 구독 삭제" -Status SKIP -Detail "GCP 를 사용하지 않았거나 gcloud 가 없습니다."
        }
        else {
            $d = Invoke-Gcloud -Name "F3-describe" -ArgumentList @("pubsub", "subscriptions", "describe", "edr-debug-sub", "--format=value(name)")
            if ($d.ExitCode -ne 0) {
                Add-Result -Id "F3" -Title "디버그 구독 삭제" -Status SKIP -Detail "edr-debug-sub 구독이 없습니다."
            }
            else {
                $del = Invoke-Gcloud -Name "F3-delete" -ArgumentList @("pubsub", "subscriptions", "delete", "edr-debug-sub")
                if ($del.ExitCode -eq 0) { Add-Result -Id "F3" -Title "디버그 구독 삭제" -Status PASS -Detail "edr-debug-sub 삭제" }
                else { Add-Result -Id "F3" -Title "디버그 구독 삭제" -Status FAIL -Detail (Get-HeadText -Text $del.StdErr -Lines 2) }
            }
        }
    }
    catch {
        Add-Result -Id "F3" -Title "디버그 구독 삭제" -Status FAIL -Detail $_.Exception.Message
    }

    # ---- F4 _Default 싱크 다시 끄기 --------------------------------------------------------
    try {
        if ($ctx.DefaultSinkEnabled -ne $true) {
            Add-Result -Id "F4" -Title "_Default 싱크 다시 끄기" -Status SKIP -Detail "이 실행이 _Default 싱크를 켜지 않았습니다."
        }
        else {
            $off = Invoke-Gcloud -Name "F4-sink-off" -ArgumentList @("logging", "sinks", "update", "_Default", "--disabled")
            $chk = Invoke-Gcloud -Name "F4-sink-check" -ArgumentList @("logging", "sinks", "list", "--format=json")
            $def = @(ConvertFrom-JsonItems $chk.StdOut | Where-Object { $_.name -eq "_Default" }) | Select-Object -First 1
            if ($off.ExitCode -eq 0 -and $def -and $def.disabled -eq $true) {
                $ctx.DefaultSinkEnabled = $false
                Add-Result -Id "F4" -Title "_Default 싱크 다시 끄기" -Status PASS -Detail "_Default 비활성 확인"
            }
            else {
                Add-Result -Id "F4" -Title "_Default 싱크 다시 끄기" -Status FAIL `
                    -Detail ("종료 코드 " + $off.ExitCode + " | 수집 요금이 계속 날 수 있으니 gcloud logging sinks update _Default --disabled 를 직접 실행하세요.")
            }
        }
    }
    catch {
        Add-Result -Id "F4" -Title "_Default 싱크 다시 끄기" -Status FAIL -Detail $_.Exception.Message
    }

    # ---- F5 테스트 데이터와 프로젝트 정리 ----------------------------------------------------
    # 기본값은 삭제하지 않음이다. BigQuery 데이터셋 삭제는 프로젝트 ID 를 직접 입력해야 진행하고,
    # 프로젝트 삭제는 되돌릴 수 없으므로 이 스크립트가 하지 않는다.
    try {
        if (-not $haveGcp -or -not $ctx.GcpTouched) {
            Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status SKIP -Detail "GCP 를 변경하지 않았습니다."
        }
        elseif ($ctx.AutoYes) {
            Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status MANUAL `
                -Detail "-Yes 실행에서는 삭제하지 않습니다. 더 쓰지 않으면 콘솔에서 프로젝트를 삭제하거나 events/alerts 의 30일 만료에 맡기세요."
        }
        else {
            Write-Host ""
            Write-Host "BigQuery 데이터셋 edr_logs (events, alerts)를 지우면 Function 이 더 이상 적재하지 못합니다." -ForegroundColor Yellow
            $typed = Read-Host "지우려면 프로젝트 ID 를 정확히 입력하세요 (Enter=지우지 않음)"
            if ($typed.Trim() -eq $project) {
                $bq = Resolve-Tool "bq"
                $rm = Invoke-Captured -Name "F5-bq-rm" -FilePath $bq -TimeoutSec 180 `
                    -ArgumentList @("rm", "-r", "-f", "-d", ("--project_id=" + $project), ($project + ":edr_logs"))
                if ($rm.ExitCode -eq 0) {
                    Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status PASS `
                        -Detail "데이터셋 edr_logs 삭제. 프로젝트를 더 쓰지 않으면 콘솔에서 삭제하고 결제 항목이 늘지 않는지 확인하세요."
                }
                else {
                    Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status FAIL -Detail (Get-HeadText -Text $rm.StdErr -Lines 2)
                }
            }
            else {
                Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status MANUAL `
                    -Detail "삭제하지 않았습니다. 더 쓰지 않으면 콘솔에서 프로젝트를 삭제하거나 30일 파티션 만료에 맡기세요."
            }
        }
    }
    catch {
        Add-Result -Id "F5" -Title "테스트 데이터와 프로젝트 정리" -Status FAIL -Detail $_.Exception.Message
    }

    # ---- F6 임시 파일 ---------------------------------------------------------------------------
    # 로그 폴더의 수집 파일(*.ndjson)은 00_run.ps1 의 -DeleteArtifacts 로 지운다.
    # 이 스크립트 밖에서 만든 파일($env:TEMP\edr-dry.ndjson 등)은 건드리지 않는다.
    Add-Result -Id "F6" -Title "임시 파일 삭제" -Status MANUAL `
        -Detail ("명령줄이 들어 있는 수집 파일을 지우세요: 로그 폴더 " + $ctx.LogDir + " 의 *.ndjson (-DeleteArtifacts), 직접 만든 edr-dry.ndjson 등")
}
