##
##  <copyright file="WossLogCollector.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

<#
.SYNOPSIS
    Collect All WOSS related logs/events/... for Diagonistic

.DESCRIPTION

.PARAMETER $After
    The start time for collected logs

.PARAMETER  $Before
    The end time for collected logs

.PARAMETER  $TragetFolderPath
    The targetPosition unc path
    
.PARAMETER  $AzureStorageAccountName
    Stored the logs into Public Azure account

.PARAMETER $AzureStorageAccountKey
    Public Azure account key
    
.PARAMETER $AzureSASToken
    Public Azure sas Token
    
.PARAMETER $AzureBlobContainer
    Public Azure blob Container name

.PARAMETER  Credential
    The PSCredential object to run this script

.PARAMETER  $SettingsStoreLiteralPath
    The Woss Settings Store location
    
.PARAMETER  $WindowsFabricEndpoint
    The targetPosition unc path 

.PARAMETER  $LogPrefix
    The Prefix for all the logs stored in public Azure blob
    
.EXAMPLE
    $secpasswd = ConvertTo-SecureString "Password!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($UserName, $secpasswd)
    $start = Get-Date -Date "2015-08-17 08:00:00"
    $end=Get-Date -Date "2015-08-17 09:00:00"

    . .\Invoke-WossLogCollector.ps1
    Invoke-WossLogCollector -StartTime $start -EndTime $end -Credential $credential -TargetFolderPath \\shared\SMB\LogCollect -AzureStorageAccountName azureaccount -AzureStorageAccountKey accountkey -AzureBlobContainer aalog -Verbose
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\WossNodeLogCollector.ps1"
. "$PSScriptRoot\Upload-WossLogs.ps1"
. "$PSScriptRoot\EstablishSmbConnection.ps1"

function Invoke-WossLogCollector
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DateTime] $StartTime,
        [Parameter(Mandatory = $true)]
        [System.DateTime] $EndTime,
        [Parameter(Mandatory = $false)]
        [PSCredential] $Credential, 
        [Parameter(Mandatory = $false)]
        [System.String] $TargetFolderPath,
        [Parameter(Mandatory = $false)]
        [System.String] $AzureStorageAccountName,
        [Parameter(Mandatory = $false)]
        [System.String] $AzureStorageAccountKey,
        [Parameter(Mandatory = $false)]
        [System.String] $AzureSASToken,
        [Parameter(Mandatory = $false)]
        [System.String] $AzureBlobContainer,
        [Parameter(Mandatory = $false)]
        [System.String] $SettingsStoreLiteralPath,
        [Parameter(Mandatory = $false)]
        [System.String[]] $WindowsFabricEndpoint,
        [Parameter(Mandatory = $false)]
        [System.String] $LogPrefix
    )

    Write-Verbose "Set error action to Stop."
    $ErrorActionPreference = "Stop"
    
    Import-Module "$PSScriptRoot\LogCollectorCmdlets.psd1"

    if($LogPrefix -eq $null){
        $LogPrefix = get-date -Format yyyyMMddHHmmss
    }
    $LogPrefix += "\"
    
    if([string]::IsNullOrEmpty($SettingsStoreLiteralPath))
    {
        $settingskey = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\WOSS\Deployment"
        $SettingsStoreLiteralPath = $settingskey.SettingsStore
    }

    $tempLogFolder = Join-Path $env:TEMP ([System.Guid]::NewGuid())
    New-Item -ItemType directory -Path $tempLogFolder
    Write-Verbose "Temp foler is $tempLogFolder"
    
    if($Credential -ne $null)
    {
        $username = $Credential.GetNetworkCredential().UserName
        $password = $Credential.GetNetworkCredential().Password
    }
    
    if(![string]::IsNullOrEmpty($TargetFolderPath))
    {
        Write-Verbose "Establish SMB connection to TargetFolder"
        if($Credential -ne $null)
        {
            EstablishSmbConnection -remoteUNC $TargetFolderPath -username $username -password $password
        }
        else
        {
            net use $TargetFolderPath
        }
        $OriTargetFolderPath = $TargetFolderPath
        $TargetFolderPath = Join-Path $TargetFolderPath (get-date -Format yyyyMMddHHmmss)
        if(!(Test-Path -Path $TargetFolderPath)){
            New-Item -ItemType directory -Path $TargetFolderPath
        }
    }

    Write-Verbose "Copy Settings Store..."

    $settingsPrefix = $LogPrefix + "Settings\"
    Upload-WossLogs -LogPaths $SettingsStoreLiteralPath.TrimStart("file:") -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $settingsPrefix

    Write-Verbose "Get Deploy Settings..."

    $settingsCommonDllPath = Join-Path $PSScriptRoot  "SettingsCommon.dll"
    $settingsManagerDllPath = Join-Path $PSScriptRoot  "SettingsManager.dll"
    $settingsReaderDllPath = Join-Path $PSScriptRoot  "SettingsReader.dll"
    
    Add-Type -Path $settingsCommonDllPath
    Add-Type -Path $settingsManagerDllPath
    Add-Type -Path $settingsReaderDllPath
    
    $settingManager = new-object Microsoft.ObjectStorage.Settings.Manager.SettingsManager -ArgumentList @($SettingsStoreLiteralPath)
    
    $Settings = $settingManager.Get()

    $clusterStatusFile = Join-Path $tempLogFolder "WossDeploymentStatus.txt"
    $Settings["Deployment"].GetEnumerator() | Export-Csv $clusterStatusFile
    
    Upload-WossLogs -LogPaths $clusterStatusFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Verbose "Get Woss Node List"
    $WossNodeList = (Get-WossNodes -SettingsStorePath $SettingsStoreLiteralPath -Credential $Credential)
    
    Write-Output "Perparation Completed"

    Write-Verbose "Set error action to Continue."
    $ErrorActionPreference = "Continue"

    $wfStatusFile = Join-Path $tempLogFolder "WindowsFabricHealthStatus.txt"
    Write-Verbose "Connect to Windows Fabric..."
    if($WindowsFabricEndpoint -eq $null)
    {
        Connect-WindowsFabricCluster
    }
    else
    {
        Connect-WindowsFabricCluster -ConnectionEndpoint $WindowsFabricEndpoint
    }
    Get-WindowsFabricClusterHealth > $wfStatusFile
    
    Upload-WossLogs -LogPaths $wfStatusFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Output "Get Windows Fabric Health Status Completed"

    $reader = New-Object Microsoft.ObjectStorage.Settings.Reader.SettingsReader($SettingsStoreLiteralPath)
    $reader.Initialize([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsSettingSectionName, $null)
    $metricsAccountName = $reader.GetSettingsValue([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsAccountNameKey, [String]::Empty, $true)
    $metricsAccountKeySecStr = $reader.GetEncryptedSettingsValue([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsSettingSectionName, [Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsAccountKeyKey)
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($metricsAccountKeySecStr)
    $metricsAccountKey = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
    
    $tableEndpoint = $Settings["Metrics"]["MetricsTableEndpoint"]
    $tableEndpoint = $tableEndpoint -f $metricsAccountName

    Write-Verbose "Get Woss Events ..."
    $wossEventFile = Join-Path $tempLogFolder "WossEvents.csv"
    
    $azureStorageDllPath = Join-Path $PSScriptRoot "Microsoft.WindowsAzure.Storage.dll"
    $eventLibPath = Join-Path $PSScriptRoot "EventLib.dll"

    Add-Type -Path $azureStorageDllPath
    Add-Type -Path $eventLibPath
    $EventClient = new-object Microsoft.ObjectStorage.Diagnostics.Event.EventClient -ArgumentList @($tableEndpoint, $metricsAccountName, $metricsAccountKey)
    $timeoutWatch = new-object Microsoft.ObjectStorage.Diagnostics.TimeoutWatch -ArgumentList @(120000)
    $events = $EventClient.GetEvents($StartTime, $EndTime, $timeoutWatch)

    $events | Export-Csv -Path $wossEventFile
    
    Upload-WossLogs -LogPaths $wossEventFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
    Write-Output "Get Woss Events Completed"

    Write-Verbose "Get Woss Faults ..."
    $farmId = $Settings["Shared"]["FarmID"]
    Try {
        $faults = Get-WossFault -StartTime $StartTime -EndTime $EndTime -FarmId $farmId -WindowsFabricEndpoint $WindowsFabricEndpoint
    }
    Catch {
        Write-Error $Error[0].Exception
    }

    $wossFaultFile = Join-Path $tempLogFolder "WossFaults.csv"

    $faults | Export-Csv -Path $wossFaultFile
    Upload-WossLogs -LogPaths $wossFaultFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Output "Get Woss Faults Completed"

    Write-Verbose "Get Woss PerfCounter ..."
    foreach ($node in $WossNodeList.GetEnumerator())
    {
        Write-Verbose "Start collect perfcounter for Node: $($node.Key)"
        $wossPerfCounterFile = Join-Path $tempLogFolder ("WossPerfCounter_{0}.txt" -f $($node.Key))
        Get-WossPerfCounter -StartTime $StartTime -EndTime $EndTime -AccountName $metricsAccountName -AccountKey $metricsAccountKey -TableEndpoint $tableEndpoint -ResourceId $($node.Key) > $wossPerfCounterFile           
        
        Upload-WossLogs -LogPaths $wossPerfCounterFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
        Write-Verbose "Complete collect perfcounter for Node: $($node.Key)"
    }
    Write-Output "Get Woss Performance Counter Completed"

    Write-Verbose "Trigger Log collect on Each Woss Node"
    # temp solution, hardcode SRP node as local machine
    $WossNodeList.Add($env:computername,("SRP"))
    
    foreach ($node in $WossNodeList.GetEnumerator())
    {
        $LogFolders = @()
        $roleList = @()
        foreach ($role in $node.Value)
        {
            if($role -eq "BlobSvc") {
                $logpath = $Settings[$role]["CosmosLogDirectory"]
            }
            else {
                # temp solution, hardcode SRP path 
                if($role -eq "SRP") {
                    $logpath = "%programdata%\WOSS\ResourceProvider"
                }
                else {
                    $logpath = $Settings[$role]["LogPath"]
                }
            }
            if($logpath -ne $null) {
                $logpath = [System.Environment]::ExpandEnvironmentVariables($logpath)
                $logpath = "\\$($node.Key)\" + $logpath.replace(":","$")
                $LogFolders += $logpath
            }
            $roleList += $role
        }
        if($LogFolders.Count -gt 0)
        {
            $uniLogFolders = $LogFolders | select -uniq
        }
        else
        {
            $uniLogFolders = $LogFolders
        }
        Write-Verbose "Start collect on Node: $($node.Key) from $uniLogFolders"

        if($uniLogFolders.Count -gt 0)
        {
            Write-Verbose "Establish SMB connection to source Folder"
            if($Credential -ne $null)
            {
                EstablishSmbConnection -remoteUNC $uniLogFolders[0] -username $cred -password $password
            }
            else
            {
                net use -remoteUNC $uniLogFolders[0]
            }
        }

        $nodeLogPrefix = "$LogPrefix\$($node.Key)"
        Invoke-WossNodeLogCollector -RoleList $roleList -BinLogRoot $uniLogFolders -StartTime $StartTime -EndTime $EndTime -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -Credential $Credential -ComputerName $($node.Key) -LogPrefix $LogPrefix
        Write-Output "Get log on Node: $($node.Key) Completed"
    }

    Write-Output "Get Cosmos log from all nodes Completed"
    
    Write-Verbose "Get Failover Cluster log"
    foreach ($node in $WossNodeList.GetEnumerator())
    {
        if($node.Value -contains "BlobBackEndNodeList")
        {
            if($Credential -ne $null)
            {
                Invoke-Command -ComputerName $($node.Key) -Credential $Credential -ScriptBlock {Get-ClusterLog}
            }
            else
            {
                Invoke-Command -ComputerName $($node.Key) -ScriptBlock {Get-ClusterLog}
            }
            $clusterlogpath = [System.Environment]::ExpandEnvironmentVariables("%windir%\Cluster\Reports\Cluster.log")
            $clusterlogpath = "\\$($node.Key)\" + $clusterlogpath.replace(":","$")
            Upload-WossLogs -LogPaths $clusterlogpath -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            break
        }
    }
    Write-Output "Get Failover Cluster log complete"

    Write-Verbose "Get Windows Fabric Log List"
    $DCARoot = $Settings["Deployment"]["FabricDiagnosticStore"]
    $winFabLogList = Get-WossLogList -LogRoot $DCARoot -StartTime $StartTime -EndTime $EndTime -Credential $Credential

    $winFabLogFolder = Join-Path $tempLogFolder "WinFabLogs"
    New-Item -ItemType directory -Path $winFabLogFolder

    Write-Verbose "Start copying Logs in folder $winFabLogFolder start at $StartTime and End at $EndTime"
    foreach ($filepath in $winFabLogList) {
        $fileName = Split-Path -Path $filepath -Leaf
        $parentFolder = Split-Path -Path (Split-Path -Path $filepath -Parent) -Leaf
        $destinationPath = Join-Path $winFabLogFolder $parentFolder
        
        if(!(Test-Path -Path $destinationPath )){
            New-Item -ItemType directory -Path $destinationPath
        }

        $destinationFile = Join-Path $destinationPath $fileName
        Copy-Item $filepath -Destination $destinationFile -Force -Recurse
    }
    Write-Verbose "Compact winfabric log folder"

    Add-Type -Assembly System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    $zipfilename = Join-Path $env:TEMP "winfabriclogs.zip"
    if(Test-Path -Path $zipfilename)
    {
        Remove-Item -Path $zipfilename
    }

    $fileSystemDllPath = [System.IO.Path]::Combine([System.IO.Path]::Combine($env:Windir,"Microsoft.NET\Framework64\v4.0.30319"), "System.IO.Compression.FileSystem.dll")

    Add-Type -Path $fileSystemDllPath
    [System.IO.Compression.ZipFile]::CreateFromDirectory($winFabLogFolder, $zipfilename, $compressionLevel, $false) 
    
    Upload-WossLogs -LogPaths $zipfilename -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Verbose "Log Files was compacted into $zipfilename"

    Write-Verbose "Remove win fabric temp log folder"
    Remove-Item $winFabLogFolder -Recurse -Force

    Write-Output "Get Windows Fabric Log Completed"

    if(![string]::IsNullOrEmpty($OriTargetFolderPath))
    {
        Write-Verbose "Compact log folder"
        $logName = get-date -Format yyyyMMddHHmmss
        $zipfilename = Join-Path $OriTargetFolderPath "ACSLogs_$logName.zip" 
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest

        [System.IO.Compression.ZipFile]::CreateFromDirectory($TargetFolderPath, $zipfilename, $compressionLevel, $false)
        Write-Verbose "Log Files was compacted into $zipfilename"

        Write-Verbose "Cleanup share folder" 
        Remove-Item $TargetFolderPath -Recurse -Force
    }

    Write-Verbose "Cleanup temp folder" 
    Remove-Item $tempLogFolder -Recurse -Force
    
    Write-Output "Log Collector completed."
}
