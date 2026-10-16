<#
.SYNOPSIS
  Back up the harbour database.
#>
Import-Module SqlServer
using module ./Harbour.psm1

function Backup-Harbour {
    param([string]$Path)
    # TODO: compress the backup
    Write-Host "Backing up to $Path"
}

class Snapshot { [string]$Name }

Backup-Harbour -Path C:\Backups
