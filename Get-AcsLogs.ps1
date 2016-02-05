##
##  <copyright file="Get-AcsLogs.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

param(
  $start,
  $end
)
$DestinationPath = "C:\ProgramData\Windows Fabric\xRPVM\Fabric\work\Applications\SrpServiceAppType_App1\SrpService.Code.10.105881000.160122.0200"
Copy-Item "$PSScriptRoot\WossLogCollector.ps1" -Destination $DestinationPath -Force
Copy-Item "$PSScriptRoot\WossNodeLogCollector.ps1" -Destination $DestinationPath -Force
if($end -eq $null)
{
    $end = Get-Date
}

if($start -eq $null)
{
    $start = Get-Date -Date "2015-01-01 00:00:00"
}

Set-Location $DestinationPath
. "$DestinationPath\WossLogCollector.ps1"
Invoke-WossLogCollector -StartTime $start -EndTime $end -TargetFolderPath \\sofs.azurestack.local\share -SettingsStoreLiteralPath file:\\sofs.azurestack.local\Share\ObjectStorageService\Settings -WindowsFabricEndpoint ACSVM.AzureStack.local:19000 -Verbose