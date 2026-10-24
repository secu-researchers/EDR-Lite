<#
  revoke-key.ps1 - Manage the agent's service account key.

  [UNVERIFIED] Written without being run. Read it first, then run it yourself.

  Actions:
    List    Show the user-managed keys of the agent service account (key IDs and creation times).
    Revoke  Delete one key (-KeyId). Add -DisableAccount to also disable the service account.
    New     Create a new key file (-OutFile). The path must NOT be inside this repository.

  Procedure when a key may have leaked:
    1) .\revoke-key.ps1 -ProjectId <id> -Action List
    2) .\revoke-key.ps1 -ProjectId <id> -Action Revoke -KeyId <id> -DisableAccount
    3) Review the events written since the suspected time (BigQuery edr_logs.events).
       Forged logs are treated as analysis material, not as evidence.
    4) gcloud iam service-accounts enable <service account email> --project=<id>
    5) .\revoke-key.ps1 -ProjectId <id> -Action New -OutFile <path outside the repo>
    6) Copy the new key to the guest (C:\edr\sa-key.json) and restart the agent.

  Usage:
    .\revoke-key.ps1 -ProjectId edr-lab-123456 -Action List
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [Parameter(Mandatory = $true)][ValidateSet("List", "Revoke", "New")][string]$Action,
    [string]$ServiceAccountName = "edr-logwriter",
    [string]$KeyId,
    [string]$OutFile,
    [switch]$DisableAccount
)
$ErrorActionPreference = "Stop"
$Sa = "$ServiceAccountName@$ProjectId.iam.gserviceaccount.com"

function G {
    & gcloud @args "--project=$ProjectId"
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud failed (exit $LASTEXITCODE): gcloud $($args -join ' ')"
    }
}

switch ($Action) {
    "List" {
        G iam service-accounts keys list "--iam-account=$Sa" "--managed-by=user"
    }
    "Revoke" {
        if (-not $KeyId) { throw "-KeyId is required for Revoke (see -Action List)" }
        G iam service-accounts keys delete $KeyId "--iam-account=$Sa" --quiet
        Write-Host "Key $KeyId deleted."
        if ($DisableAccount) {
            G iam service-accounts disable $Sa
            Write-Host "Service account disabled: $Sa"
        }
    }
    "New" {
        if (-not $OutFile) { throw "-OutFile is required for New" }
        $full = [System.IO.Path]::GetFullPath($OutFile)
        $repo = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
        if ($full.StartsWith($repo, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to write a key inside the repository: $full"
        }
        if (Test-Path -LiteralPath $full) { throw "File already exists: $full" }
        G iam service-accounts keys create $full "--iam-account=$Sa"
        icacls $full /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
        Write-Host "New key written to $full (readable only by the current user)."
        Write-Host "Copy it to the guest, then delete this copy once it is no longer needed."
    }
}
