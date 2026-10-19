<#
  setup.ps1 - Provision the edr-lite monitoring pipeline on GCP.

  [UNVERIFIED] Written without being run. Read it first, then run it yourself in a
  dedicated GCP project. Prerequisites: Cloud SDK (gcloud, bq) installed, `gcloud auth login`
  done, the project exists and has billing linked.

  Steps (re-running is safe where possible):
    1. Enable the required APIs
    2. Create service accounts and grant least-privilege roles
         edr-logwriter   agent key owner, Logs Writer only (write-only)
         edr-monitor-fn  Cloud Run functions runtime identity
         edr-scheduler   identity that Cloud Scheduler uses to call edr-watchdog
    3. Create the Pub/Sub topic and the BigQuery dataset and tables (schema.sql)
    4. Store the Discord webhook URL in Secret Manager (prompted, never written to disk)
    5. Create the log sink (log lab_malware -> Pub/Sub) and disable the _Default sink
    6. Deploy two functions: edr-ingest (Pub/Sub trigger) and edr-watchdog (HTTP)
    7. Create the Cloud Scheduler job that calls edr-watchdog

  Not done here (do it yourself):
    - The agent's service account key        -> revoke-key.ps1 -Action New
    - The monthly budget alert (about 5,000 KRW) -> console: Billing > Budgets & alerts

  Usage:
    .\setup.ps1 -ProjectId <dedicated-project-id>
    .\setup.ps1 -ProjectId <id> -Region asia-northeast3 -BqLocation asia-northeast3 -HeartbeatSecs 10
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$Region = "asia-northeast3",
    [string]$BqLocation = "asia-northeast3",
    [string]$LogName = "lab_malware",
    [int]$HeartbeatSecs = 10,
    [string]$WatchdogSchedule = "*/2 * * * *",
    [switch]$SkipSecret
)
$ErrorActionPreference = "Stop"

$SrcDir     = Join-Path $PSScriptRoot "functions\edr_monitor"
$SchemaFile = Join-Path $PSScriptRoot "schema.sql"
$Topic      = "edr-log-topic"
$Sink       = "edr-log-sink"
$SecretName = "edr-discord-webhook"
$IngestFn   = "edr-ingest"
$WatchFn    = "edr-watchdog"
$JobName    = "edr-watchdog-job"
$AgentSa    = "edr-logwriter@$ProjectId.iam.gserviceaccount.com"
$FnSa       = "edr-monitor-fn@$ProjectId.iam.gserviceaccount.com"
$SchedSa    = "edr-scheduler@$ProjectId.iam.gserviceaccount.com"

# Run gcloud against the target project and stop on failure.
function G {
    & gcloud @args "--project=$ProjectId"
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud failed (exit $LASTEXITCODE): gcloud $($args -join ' ')"
    }
}

# Returns $true when the gcloud command succeeds (used for exists-checks).
function Test-Gcloud {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & gcloud @args "--project=$ProjectId" 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

function Ensure-ServiceAccount {
    param([string]$Email, [string]$DisplayName)
    if (-not (Test-Gcloud iam service-accounts describe $Email)) {
        G iam service-accounts create $Email.Split("@")[0] "--display-name=$DisplayName" | Out-Null
        Write-Host "    created $Email"
    }
}

function Grant-Project {
    param([string]$Email, [string]$Role)
    G projects add-iam-policy-binding $ProjectId "--member=serviceAccount:$Email" "--role=$Role" "--condition=None" | Out-Null
}

if (-not (Test-Path -LiteralPath $SrcDir)) { throw "function source not found: $SrcDir" }
if (-not (Test-Path -LiteralPath $SchemaFile)) { throw "schema file not found: $SchemaFile" }

# ---- 1. APIs ----
Write-Host "[1/7] Enabling APIs"
G services enable `
    logging.googleapis.com bigquery.googleapis.com pubsub.googleapis.com `
    cloudfunctions.googleapis.com run.googleapis.com eventarc.googleapis.com `
    cloudbuild.googleapis.com cloudscheduler.googleapis.com secretmanager.googleapis.com `
    artifactregistry.googleapis.com compute.googleapis.com

# ---- 2. Service accounts and roles ----
Write-Host "[2/7] Service accounts and roles"
Ensure-ServiceAccount $AgentSa "edr agent log writer (write-only)"
Ensure-ServiceAccount $FnSa "edr monitor functions"
Ensure-ServiceAccount $SchedSa "edr scheduler caller"
Start-Sleep -Seconds 15   # let the new accounts propagate before binding roles

Grant-Project $AgentSa "roles/logging.logWriter"
Grant-Project $FnSa "roles/bigquery.dataEditor"
Grant-Project $FnSa "roles/bigquery.jobUser"
Grant-Project $FnSa "roles/eventarc.eventReceiver"

# Source deployments build with the default compute service account on many projects.
try {
    $projectNumber = (& gcloud projects describe $ProjectId '--format=value(projectNumber)').Trim()
    Grant-Project "$projectNumber-compute@developer.gserviceaccount.com" "roles/cloudbuild.builds.builder"
}
catch {
    Write-Warning "Could not grant the build role to the default compute account. If the deploy step fails on build permissions, grant roles/cloudbuild.builds.builder to it manually."
}

# ---- 3. Pub/Sub topic and BigQuery ----
Write-Host "[3/7] Pub/Sub topic and BigQuery tables"
if (-not (Test-Gcloud pubsub topics describe $Topic)) {
    G pubsub topics create $Topic | Out-Null
}
$lines = Get-Content -LiteralPath $SchemaFile -Encoding UTF8 |
    ForEach-Object { $_ -replace '\s*--.*$', '' } |
    Where-Object { $_.Trim() -ne '' }
$sql = ($lines -join "`n").Replace("<PROJECT_ID>", $ProjectId).Replace("<LOCATION>", $BqLocation)
$sql | & bq query --use_legacy_sql=false "--location=$BqLocation" "--project_id=$ProjectId"
if ($LASTEXITCODE -ne 0) { throw "bq query failed while applying schema.sql" }

# ---- 4. Discord webhook secret ----
Write-Host "[4/7] Discord webhook secret"
$secretArgs = @()
if ($SkipSecret) {
    Write-Host "    skipped (-SkipSecret): functions will log a warning and send no alerts"
}
else {
    if (-not (Test-Gcloud secrets describe $SecretName)) {
        $secure = Read-Host "Discord webhook URL (input is hidden)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plain | & gcloud secrets create $SecretName --data-file=- --replication-policy=automatic "--project=$ProjectId" | Out-Null
        $plain = $null
        if ($LASTEXITCODE -ne 0) { throw "failed to create the secret" }
    }
    G secrets add-iam-policy-binding $SecretName "--member=serviceAccount:$FnSa" "--role=roles/secretmanager.secretAccessor" | Out-Null
    $secretArgs = @("--set-secrets=DISCORD_WEBHOOK_URL=${SecretName}:latest")
}

# ---- 5. Log sink and _Default sink ----
Write-Host "[5/7] Log sink (log $LogName -> Pub/Sub) and _Default sink"
if (-not (Test-Gcloud logging sinks describe $Sink)) {
    G logging sinks create $Sink "pubsub.googleapis.com/projects/$ProjectId/topics/$Topic" "--log-filter=logName=projects/$ProjectId/logs/$LogName" | Out-Null
}
$writer = (& gcloud logging sinks describe $Sink '--format=value(writerIdentity)' "--project=$ProjectId").Trim()
G pubsub topics add-iam-policy-binding $Topic "--member=$writer" "--role=roles/pubsub.publisher" | Out-Null
# Logs that are not routed by a sink are not stored. Re-enable _Default only while debugging.
G logging sinks update _Default --disabled | Out-Null

# ---- 6. Functions ----
Write-Host "[6/7] Deploying functions (this takes a few minutes)"
$common = @(
    "--gen2", "--runtime=python312", "--region=$Region", "--source=$SrcDir",
    "--service-account=$FnSa", "--memory=256Mi", "--max-instances=5",
    "--set-env-vars=BQ_DATASET=edr_logs,HEARTBEAT_SECS=$HeartbeatSecs"
) + $secretArgs
G functions deploy $IngestFn @common "--entry-point=on_log_entry" "--trigger-topic=$Topic" "--trigger-service-account=$FnSa"
G functions deploy $WatchFn @common "--entry-point=watchdog" "--trigger-http" "--no-allow-unauthenticated"
G run services add-iam-policy-binding $IngestFn "--region=$Region" "--member=serviceAccount:$FnSa" "--role=roles/run.invoker" | Out-Null

# ---- 7. Scheduler ----
Write-Host "[7/7] Cloud Scheduler job"
$url = (& gcloud functions describe $WatchFn --gen2 "--region=$Region" "--project=$ProjectId" '--format=value(serviceConfig.uri)').Trim()
if (-not $url) { throw "could not read the URL of $WatchFn" }
G run services add-iam-policy-binding $WatchFn "--region=$Region" "--member=serviceAccount:$SchedSa" "--role=roles/run.invoker" | Out-Null
$jobArgs = @(
    "--location=$Region", "--schedule=$WatchdogSchedule", "--uri=$url", "--http-method=GET",
    "--oidc-service-account-email=$SchedSa", "--oidc-token-audience=$url"
)
if (Test-Gcloud scheduler jobs describe $JobName "--location=$Region") {
    G scheduler jobs update http $JobName @jobArgs | Out-Null
}
else {
    G scheduler jobs create http $JobName @jobArgs | Out-Null
}

Write-Host ""
Write-Host "Done. Remaining manual steps:"
Write-Host "  1) Create the monthly budget alert in the console (Billing > Budgets & alerts, about 5,000 KRW)."
Write-Host "     A budget only sends alerts; it does not stop spending."
Write-Host "  2) Create the agent key:  .\revoke-key.ps1 -ProjectId $ProjectId -Action New -OutFile <path outside the repo>"
Write-Host "  3) Copy the key to the guest as C:\edr\sa-key.json, fill agent.toml, run the agent with --test."
Write-Host "  4) Check BigQuery edr_logs.events for the test events and the Discord channel for alerts."
