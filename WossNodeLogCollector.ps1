##
##  <copyright file="WossNodeLogCollector.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

<#
.SYNOPSIS
    Collect All WOSS related logs/events/... for Diagonistic

.DESCRIPTION

.PARAMETER BinLogRoot
    The full path of Woss Log.

.PARAMETER BinLogRoot
    The full path of Woss Log.

.PARAMETER After
    The collected logs will all be after this datetime

.PARAMETER Before
    The collected logs will all be before this datetime

.PARAMETER  Credential
    The PSCredential object to run this script in workflow service.

.PARAMETER  $TargetPosition
    The targetPosition unc path

.EXAMPLE
    $secpasswd = ConvertTo-SecureString "Password!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($UserName, $secpasswd)
    $start = Get-Date -Date "2015-03-13 15:20:00"
    $end = Get-Date -Date "2015-03-13 15:30:00"
    . .\Invoke-WossNodeLogCollector.ps1
    Invoke-WossNodeLogCollector -RoleList ("TSNodeList","TMNodeList") -Credential $credential -BinLogRoot E:\WOSSLog -StartTime $start -EndTime $end $TargetFolderPath "\\Share\WossLogShare"
#>

function Invoke-WossNodeLogCollector
{
[CmdletBinding()]
param(
        [Parameter(Mandatory = $true)]
        [System.String[]] $RoleList,
        
        [Parameter(Mandatory = $false)]
        [System.String[]] $BinLogRoot,
        
        [Parameter(Mandatory = $true)]
        [System.DateTime] $StartTime,
        
        [Parameter(Mandatory = $true)]
        [System.DateTime] $EndTime,
        
        [Parameter(Mandatory = $true)]
        [System.String] $ComputerName,

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
        [System.String] $LogPrefix
    )
    
    . "$PSScriptRoot\Upload-WossLogs.ps1"

    Import-Module "$PSScriptRoot\LogCollectorCmdlets.psd1"

    Write-Verbose "Create temp folder..."
    $tempLogFolder = Join-Path $env:TEMP ([System.Guid]::NewGuid())
    New-Item -ItemType directory -Path $tempLogFolder
    Write-Verbose "Temp foler is $tempLogFolder"
    
    $LogPrefix = "$LogPrefix$ComputerName"
    
    Write-Verbose "Set firewall rule to enable remote log collect."
    $sc = {
        $isEventLogInEnabled = (Get-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP").Enabled
        if($isEventLogInEnabled -eq "False")
        {
            Enable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"
        }
        $isEventLogInEnabled
    }

    if($Credential -ne $null)
    {
        $isEventLogInEnabled = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $sc
    }
    else
    {
        $isEventLogInEnabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sc
    }

    $sc = {
        $isFPSEnabled = (Get-NetFirewallRule -Name "FPS-SMB-In-TCP").Enabled
        if($isFPSEnabled -eq "False")
        {
            Enable-NetFirewallRule -Name "FPS-SMB-In-TCP"
        }
        $isFPSEnabled
    }
    
    if($Credential -ne $null)
    {
        $isFPSEnabled = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $sc
    }
    else
    {
        $isFPSEnabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sc
    }

    Write-Verbose "Get Cosmos Log file List"

    if($BinLogRoot -ne $null)
    {
        foreach ($root in $BinLogRoot) {
            $CosmosLogList = Get-WossLogList -LogRoot $root -StartTime $StartTime -EndTime $EndTime -Credential $Credential
            if(($CosmosLogList -ne $null) -and ($CosmosLogList.count -gt 0)){
                Upload-WossLogs -LogPaths $CosmosLogList -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            }
            else
            {
                Write-Verbose "$root has no log to copy."
            }
        }
        Write-Verbose "Cosmos logs copy complete."
    }

    if($RoleList.Contains("TableServer") -or $RoleList.Contains("TableMaster") -or $RoleList.Contains("AccountAndContainer") -or $RoleList.Contains("Metrics"))
    {
        Write-Verbose "Collect ESENT Events."
        $applicationEventFile = Join-Path $tempLogFolder "ApplicationEvent.csv"
        $smbClientEventFile = Join-Path $tempLogFolder "SMBClientEvent.csv"
        $wossEventFile = Join-Path $tempLogFolder "ACSEvent.csv"
        
        if($Credential -ne $null)
        {
            Get-WinEvent -LogName Application -ComputerName $ComputerName -Credential $Credential | Export-Csv $applicationEventFile
            Get-WinEvent -ProviderName "Microsoft-Windows-SMBClient" -ComputerName $ComputerName -Credential $Credential | Export-Csv $smbClientEventFile
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS" -ComputerName $ComputerName -Credential $Credential | Export-Csv $wossEventFile
        }
        else
        {
            Get-WinEvent -LogName Application -ComputerName $ComputerName | Export-Csv $applicationEventFile
            Get-WinEvent -ProviderName "Microsoft-Windows-SMBClient" -ComputerName $ComputerName | Export-Csv $smbClientEventFile
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS" -ComputerName $ComputerName | Export-Csv $wossEventFile
        }
        
        Upload-WossLogs -LogPaths $applicationEventFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
        Upload-WossLogs -LogPaths $smbClientEventFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
        Upload-WossLogs -LogPaths $wossEventFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

        Write-Verbose "Finish collecting ESENT and SMBClient events"
    }

    if($RoleList.Contains("SRP"))
    {
        Write-Verbose "Collect Woss Srp Events."

        $wossEventFile = Join-Path $tempLogFolder "ACSRPEvent.csv"
        if($Credential -ne $null)
        {
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS-ResourceProvider" -ComputerName $ComputerName -Credential $Credential | Export-Csv $wossEventFile
        }
        else
        {
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS-ResourceProvider" -ComputerName $ComputerName | Export-Csv $wossEventFile
        }

        Upload-WossLogs -LogPaths $wossEventFile -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
    }
    
    
    Write-Verbose "Collect Dump files"
    if($Credential -ne $null)
    {
        $dumpkeys = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"}
    }
    else
    {
        $dumpkeys = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"}
    }
    $collectDumpExeNameList = ("blobsvc.exe","Fabric.exe","FabricDCA.exe","FabricGateway.exe","FabricHost.exe","FabricIS.exe","FabricMdsAgentSvc.exe","FabricMonSvc.exe","FabricMonSvc.exe","FabricRM.exe","FabricRS.exe","FrontEnd.Table.exe","FrontEnd.Blob.exe","FrontEnd.Queue.exe","Metrics.exe","TableMaster.exe","TableServer.exe","MonAgentHost.exe","AgentCore.exe")

    foreach ($dumpkey in $dumpkeys)
    {
        $isExeContained = $collectDumpExeNameList.Contains($dumpkey.Name)
        if($isExeContained)
        {
            $dumpFolder = ($dumpkey| Get-ItemProperty).DumpFolder
            
            $dumpFolder = "\\$ComputerName\" + $dumpFolder.replace(":","$")
            
            $dumpfiles = Get-ChildItem $dumpFolder | Where{$_.CreationTime -ge $StartTime -and $_.CreationTime -le $EndTime}
            foreach ($dumpfilePath in $dumpfiles) {
                $dumpFileName = Split-Path -Path $dumpfilePath -Leaf
                if(!(Test-Path -Path $dumpDestinationPath )){
                    New-Item -ItemType directory -Path $dumpDestinationPath
                }

                Upload-WossLogs -LogPaths $dumpfilePath -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureStorageAccountKey -AzureSASToken $AzureSASToken -AzureBlobContainer $AzureBlobContainer -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            }
        }
    }
    Write-Verbose "Finish collecting Dump files" 
    
    Write-Verbose "Cleanup temp folder" 
    Remove-Item $tempLogFolder -Recurse -Force
    
    Write-Verbose "Reset firewall status back."
    
    if($isEventLogInEnabled -eq "False"){
        if($Credential -ne $null)
        {
            Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Disable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"}
        }
        else
        {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Disable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"}
        }
    }

    if($isFPSEnabled -eq "False"){
        if($Credential -ne $null)
        {
            Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Disable-NetFirewallRule -Name "FPS-SMB-In-TCP"}
        }
        else
        {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Disable-NetFirewallRule -Name "FPS-SMB-In-TCP"}
        }        
    }

    Write-Verbose "Node $ComputerName Log Collector completed."
}