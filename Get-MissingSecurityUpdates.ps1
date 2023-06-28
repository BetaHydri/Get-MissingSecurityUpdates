#requires -Version 4

<#PSScriptInfo

.VERSION 1.0.1

.GUID 7b36f1ec-fad5-48d6-adee-bd5a5d437bea

.AUTHOR Jan-Andre Tiedemann, Andreas Mirbach, Jan-Hendirk Peters

.COMPANYNAME Microsoft GmbH

.COPYRIGHT Microsoft GmbH

.TAGS PSScript

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
Amended by Jan Tiedemann to run offline, added automated download capability of wsusscn2.cab file and parameter handling

#>

<# 

.DESCRIPTION 
 A CASE script to search for missing security updates used in the Microsoft Baseline Security Analyser 

#> 
[CmdletBinding(DefaultParameterSetName = 'ComputerName')]
param
(
    # Target machine name or comma seperated string for multiple computers like 'server1,server2'
    [Parameter(Position = 0, 
        Mandatory = $true, 
        ParameterSetName = 'ComputerName', 
        HelpMessage = "Target machine name or comma seperated string for multiple Computers like 'server1,server2'")]
    [System.String]$ComputerName,

    # Target machines as text file each line one server
    [Parameter(Position = 0, 
        Mandatory = $true, 
        ParameterSetName = 'ServerFile', 
        HelpMessage = "Target machines as text file each line one server")]
    [System.String]$Servers_file,

    # CabPath to wsusscn2.cab e.g. c:\wsusscn2.cab
    [Parameter(Position = 1, 
        Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [System.String]$CabPath = (Join-Path -Path $env:SystemDrive -ChildPath wsusscn2.cab),
	
    # UpdateSearchFilter e.g. 'IsHidden=0 and IsInstalled=0' to retrieve 'Missing Updates' including hidden ones.
    [Parameter(Position = 2, 
        Mandatory = $false,
        HelpMessage = "Filter to show e.g. only missing updates 'IsInstalled=0' or all updates 'IsHidden=0'")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('IsHidden=0 and IsInstalled=0', 'IsHidden=0', 'IsInstalled=0')]
    [System.String]$UpdateSearchFilter,
	
    # Pass new PsCredentials for WinRM Remoting if needed
    [Parameter(Position = 3)]
    [PSCredential]$Credential
)

Set-Location -Path .

function Send-File {
    <#
            .SYNOPSIS

            Sends a file to a remote session.

            .EXAMPLE

            PS >$session = New-PsSession leeholmes1c23
            PS >Send-File c:\temp\test.exe c:\temp\test.exe $session
    #>
	
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Source,
		
        [Parameter(Mandatory = $true)]
        [string]
        $Destination,
		
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        $ChunkSize = 1MB
    )
	
    #Set-StrictMode -Version Latest
    $firstChunk = $true
	
    Write-Host ('PSFileTransfer: Sending file {0} to {1} on {2} ({3} MB chunks)' -f $Source, $Destination, $Session.ComputerName, [Math]::Round($chunkSize / 1MB, 2))
	
    $sourcePath = (Resolve-Path $Source -ErrorAction SilentlyContinue).Path
    if (-not $sourcePath) {
        Write-Host ('Source file {0} could not be found' -f $Source)
        throw ('Source file {0} could not be found' -f $Source)
    }
	
    $sourceFileStream = [IO.File]::OpenRead($sourcePath)
	
    for ($position = 0; $position -lt $sourceFileStream.Length; $position += $chunkSize) {        
        $remaining = $sourceFileStream.Length - $position
        $remaining = [Math]::Min($remaining, $chunkSize)
		
        $chunk = New-Object -TypeName byte[] -ArgumentList $remaining
        $null = $sourceFileStream.Read($chunk, 0, $remaining)
		
        try {
            #Write-File -DestinationFile $Destination -Bytes $chunk -Erase $firstChunk
            Invoke-Command -Session $Session -ScriptBlock (Get-Command Write-File).ScriptBlock `
                -ArgumentList $Destination, $chunk, $firstChunk -ErrorAction Stop
        }
        catch {
            Write-Host ('Could not write destination file. {0}' -f $_.Exception.Message)
            throw $_.Exception
        }
		
        $firstChunk = $false
    }
	
    $sourceFileStream.Close()
	
    Write-Host ('PSFileTransfer: Finished sending file {0}' -f $Source)
}

function Write-File {
    <#
      .SYNOPSIS
      Describe purpose of "Write-File" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER DestinationFile
      Describe parameter -DestinationFile.

      .PARAMETER Bytes
      Describe parameter -Bytes.

      .PARAMETER Erase
      Describe parameter -Erase.

      .EXAMPLE
      Write-File -DestinationFile Value -Bytes Value -Erase Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-File

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    param (
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile,
		
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
		
        [bool]$Erase
    )
	
    #Convert the destination path to a full filesytem path (to support relative paths)
    try {
        $DestinationFile = $executionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationFile)
    }
    catch {
        Write-Host ('Could not set destination path to {0} to copy item through the remote session. {1}' -f $DestinationFile, $_.Exception.Message)
        throw New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ('Could not set destination path', $_)
    }
	
    if ($Erase) {
        Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue
    }
	
    $destFileStream = [IO.File]::OpenWrite($DestinationFile)
    $destBinaryWriter = New-Object -TypeName System.IO.BinaryWriter -ArgumentList ($destFileStream)
	
    $null = $destBinaryWriter.Seek(0, 'End')
    $destBinaryWriter.Write($Bytes)
	
    $destBinaryWriter.Close()
    $destFileStream.Close()
	
    $Bytes = $null
    [GC]::Collect()
}

function Get-MissingSecurityUpdates {
    <#
    .SYNOPSIS
		Script to search for security updates installed and/or missing
	
    .NOTES
		Jan-Andre Tiedemann, Andreas Mirbach, Jan-Hendirk Peters
		Amended by Jan Tiedemann to run offline, added automated download capability of wsusscn2.cab file and parameter handling
    
    .DESCRIPTION
		A CASE script to search for missing security updates used in the Microsoft Baseline Security Analyser
    
    .PARAMETER 	ComputerName
		The machine or machines to connect to if multiple seperated by comma
    
    .PARAMETER Server_file	
		The multiple machines inside a text file
    
    .PARAMETER CabPath
		The path to the offline scan file, if file does not exists it will be downloaded via WebClient API
	
    .EXAMPLE
		GetMissingUpdates -Server_file 'c:\tmp\myservers.txt'
	
    .EXAMPLE
		GetMissingUpdates -ComputerName 'Server1,Server2,Server3'
	
    .EXAMPLE
		GetMissingUpdates -ComputerName 'Server1'
	
	.EXAMPLE
		GetMissingUpdates.ps1 -ComputerName 'jantiede-x1' -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0'
    
	.OUTPUTS
		System.String. You can pipe it into a Table and wirte it into a csv for further excel processing.
#>


    param
    (
        # Target machine name
        $ComputerName,

        # Path to c:\wsusscn2.cab
        $CabPath,

        [Parameter()]
        [System.String]
        $UpdateSearchFilter = 'IsHidden = 0',

        [Parameter()]
        [pscredential]
        $Credential
    )
    Write-Host 'Setting culture to en-US'

    $culture = New-Object -TypeName System.Globalization.CultureInfo -ArgumentList 'en-US'
    $culture.NumberFormat.NumberGroupSeparator = ','
    $culture.NumberFormat.NumberDecimalDigits = 2
    $culture.NumberFormat.NumberDecimalSeparator = '.'
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture

    Write-Host ('Creating session to {0}' -f $ComputerName)

    $sessionParameters = @{
        ComputerName = $ComputerName
        ErrorAction  = 'Stop'
        Name         = 'WuaSession'
    }

    if ($Credential) {
        $sessionParameters.Add('Credential', $Credential)
    }

    try {
        $session = New-PSSession @sessionParameters
    }
    catch {
        Write-Host ('Error establishing connection to {0}. Error message was {1}' -f $ComputerName, $_.Exception.Message) 
        Write-Error -Message ('Error establishing connection to {0}. Error message was {1}' -f $ComputerName, $_.Exception.Message) -Exception $_.Exception -TargetObject $ComputerName
        return $null
    }

    try {
        $osRoot = Invoke-Command -Session $session -ScriptBlock { $env:SystemDrive } -ErrorAction Stop
    }
    catch {
        Write-Host ('Error retrieving OS root path from {0}. Assuming issue with the connection. Error was {1}' -f $ComputerName, $_.Exception.Message)
        Write-Error -Message ('Error retrieving OS root path from {0}. Assuming issue with the connection. Error was {1}' -f $ComputerName, $_.Exception.Message)
    }

    try {
        $osPSVersion = Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion.Major } -ErrorAction Stop
    }
    catch {
        Write-Host ('Error retrieving OS Powershell version from {0}. Assuming issue with the connection. Error was {1}' -f $ComputerName, $_.Exception.Message)
        Write-Error -Message ('Error retrieving OS Powershell version from {0}. Assuming issue with the connection. Error was {1}' -f $ComputerName, $_.Exception.Message)
    }

    $adminShare = '\\{0}\{1}$' -f $ComputerName, ($osRoot -replace '[:\\]')
    $useSmb = Test-Path $adminShare

    $destination = (Join-Path -Path $osRoot -ChildPath Windows\Temp\wsusscn2.cab)

    if ($useSmb) {
        $smbDestination = (Join-Path -Path $adminShare -ChildPath Windows\Temp\wsusscn2.cab)

        try {
            Write-Host ('Using Copy-Item to copy {0} to {1} on {2}' -f $CabPath, $smbDestination, $ComputerName)
            Copy-Item -Path $CabPath -Destination $smbDestination -Force -ErrorAction Stop
        }
        catch {
            Write-Host ('Error copying {0} to {1} on target machine {2}' -f $CabPath, $smbDestination, $ComputerName)
            Write-Error -Exception $_.Exception -Message ('Error copying {0} to {1} on target machine {2}' -f $CabPath, $smbDestination, $ComputerName) -TargetObject $CabPath -Category InvalidOperation
            return $null
        }
    }
    else {
        try {
            if ($PSVersionTable.PSVersion.Major -lt 5 -or $osPSVersion -lt 3) {
                Write-Host ('Using Send-File to copy {0} to {1} on {2} in 1MB chunks' -f $CabPath, $destination, $ComputerName)
                Send-File -Source $CabPath -Destination $destination -Session $session -ChunkSize 1MB -ErrorAction Stop
            }
            else {
                Write-Host ('Using Copy-Item -ToSession to copy {0} to {1} on {2}' -f $CabPath, $destination, $ComputerName)
                Copy-Item -ToSession $session -Path $CabPath -Destination $destination -ErrorAction Stop
            }
        }
        catch {
            Write-Host ('Error copying {0} to {1} on target machine {2}' -f $CabPath, $destination, $ComputerName)
            Write-Error -Exception $_.Exception -Message ('Error copying {0} to {1} on target machine {2}' -f $CabPath, $destination, $ComputerName) -TargetObject $CabPath -Category InvalidOperation
            return $null
        }
    }
    

    $remoteScript = {
        [CmdletBinding()]
        param
        (
            [string]$destination,
            [string]$UpdateSearchFilter,
            $remoteScript
        )

        Add-Type -TypeDefinition '
        public enum MsrcSeverity
        {
            Unspecified,
            Low,
            Moderate,
            Important,
            Critical
        }
        ' -ErrorAction SilentlyContinue

        
        try {
            if (@(1, 2, 3, 4, 6, 11, 27, 28) -contains (Get-WmiObject Win32_OperatingSystem).OperatingSystemSKU -and $remoteScript) {
                # Client SKUs
                Write-Host 'Client SKU. Registering script as scheduled task'
                $localScript = [scriptblock]::Create($remoteScript)
                if (Get-ScheduledJob WorkaroundJob -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledJob -Name WorkaroundJob -Force
                }

                # On client SKUs, WU-APIs are remoting-aware. We trick them be starting a scheduled job
                $jobOption = New-ScheduledJobOption -RunElevated -StartIfOnBattery -ContinueIfGoingOnBattery
                $job = Register-ScheduledJob -ScriptBlock $localScript -Name WorkaroundJob -ArgumentList @($destination, $UpdateSearchFilter) -ScheduledJobOption $jobOption
                $job.RunAsTask()

                Start-Sleep -Seconds 1

                $job = Get-Job -Name WorkaroundJob -ErrorAction Stop | Where-Object -Property State -EQ Running

                $jobResult = $job | Wait-Job | Receive-Job
                return $jobResult
            }
        }
        # NOTE: When you use a SPECIFIC catch block, exceptions thrown by -ErrorAction Stop MAY LACK
        # some InvocationInfo details such as ScriptLineNumber.
        # REMEDY: If that affects you, remove the SPECIFIC exception type [System.Management.Automation.PSArgumentException] in the code below
        # and use ONE generic catch block instead. Such a catch block then handles ALL error types, so you would need to
        # add the logic to handle different error types differently by yourself.
        catch [System.Management.Automation.PSArgumentException] {
            # get error record
            [Management.Automation.ErrorRecord]$e = $_

            # retrieve information about runtime error
            $info = [PSCustomObject]@{
                Exception = $e.Exception.Message
                Reason    = $e.CategoryInfo.Reason
                Target    = $e.CategoryInfo.TargetName
                Script    = $e.InvocationInfo.ScriptName
                Line      = $e.InvocationInfo.ScriptLineNumber
                Column    = $e.InvocationInfo.OffsetInLine
            }
          
            # output information. Post-process collected info, and log info (optional)
            $info
        }


        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager

        try {
            $UpdateService = $UpdateServiceManager.AddScanPackageService('Offline Sync Service', $Destination)
        }
        catch {
            $exceptionObject = $_
            switch (('{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult)) {
                # E_ACCESSDENIED
                '80070005' {
                    Write-Error -Message 'AddScanPackageService received an AccessDenied exception.' -Exception $exceptionObject.Exception -Category PermissionDenied -TargetObject $Destination
                    return $null
                }
                # E_INVALIDARG
                '80070057' {
                    Write-Error -Message ('AddScanPackageService received one or more invalid arguments. Arguments were {0}, {1}' `
                            -f 'Offline Sync Service', $Destination) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                # File not found
                '80070002' {
                    Write-Error -Message ('{0} could not be found.' -f $Destination) -Exception $exceptionObject.Exception -Category ObjectNotFound -TargetObject $Destination
                    return $null
                }
                default {
                    throw $exceptionObject
                }
            }
        }        

        try {
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        }
        catch {
            Write-Error -Message 'CreateUpdateSearcher threw a generic error' -Exception $_.Exception -TargetObject $UpdateSession
        }

        # corresponds to ss_others https://msdn.microsoft.com/en-us/library/windows/desktop/aa387280(v=vs.85).aspx
        $UpdateSearcher.ServerSelection = 3
        $UpdateSearcher.ServiceID = $UpdateService.ServiceID
        #$UpdateSearcher.Online = $false

        # Initiate the search
        try {
            $SearchResult = $UpdateSearcher.Search($UpdateSearchFilter)
        }
        catch {
            $exceptionObject = $_
            switch (('{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult)) {
                #WU_E_LEGACYSERVER
                '80004003' {
                    Write-Error -Message ('Target {0} is Microsoft Software Update Services (SUS) 1.0 server.' -f $ComputerName) -Exception $exceptionObject.Exception
                    return $null
                }
                #E_POINTER
                '8024002B' {
                    Write-Error -Message ('Search received invalid argument {0}' `
                            -f $UpdateSearchFilter) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                #WU_E_INVALID_CRITERIA
                '80240032' {
                    Write-Error -Message ('Invalid search filter: {0}' `
                            -f $UpdateSearchFilter) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                default {
                    throw $exceptionObject
                }
            }
        }
        
        $missingUpdates = @()
        foreach ($result in $SearchResult.Updates) {
            $downloadUrl = $result.BundledUpdates | ForEach-Object {
                $_.DownloadContents | ForEach-Object {
                    $_.DownloadUrl
                }
            } | Select-Object -First 1

            $severity = 0

            try {
                $severity = ([int][MsrcSeverity]$result.MsrcSeverity)
            }
            catch 
            { }

            $bulletinId = ($result.SecurityBulletinIDs | Select-Object -First 1)
            $bulletinUrl = if ($bulletinId) {
                'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
            }
            else {
                [System.String]::Empty
            }    
            #$result | get-member
            $update = New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name Computer -Value "$env:computername" -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name Id -Value ($result.SecurityBulletinIDs | Select-Object -First 1) -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name CVEIds -Value ($result.cveids | Select-Object -First 1) -PassThru -Force |
            #Add-Member -MemberType NoteProperty -Name Guid -Value $result.Identity.UpdateId -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name BulletinId -Value $bulletinId -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name KbId -Value ($result.KBArticleIDs | Select-Object -First 1) -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name Type -Value $result.Type -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name IsInstalled -Value $result.IsInstalled -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name RestartRequired -Value $result.RebootRequired -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name Title -Value $result.Title -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name Description -Value $result.Description -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name SeverityText -Value $result.MsrcSeverity -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name Severity -Value $severity -PassThru -ErrorAction SilentlyContinue -Force |
            Add-Member -MemberType NoteProperty -Name InformationURL -Value ($result.MoreInfoUrls | Select-Object -First 1) -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name SupportURL -Value $result.supporturl -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -PassThru -Force |
            Add-Member -MemberType NoteProperty -Name BulletinURL -Value $bulletinUrl -PassThru -Force

            $missingUpdates += $update
        }

        try {
            Write-Host ('Removing WSUS offline file {0}' -f $Destination)
            Remove-Item -Path $Destination -Force -ErrorAction Stop
        }
        catch {
            Write-Warning -Message ('WSUS offline file {0} could not be removed. Error was {1}' -f $Destination, $_.Exception.Message)
        }
        return $missingUpdates
    }

    $returnValues = Invoke-Command -Session $session -ScriptBlock $remoteScript -HideComputerName -ErrorAction Stop -ArgumentList ($destination, $UpdateSearchFilter, $remoteScript)
    $session | Remove-PSSession

    return $returnValues
}

function Get-WsusCab {
    <#
      .SYNOPSIS
      Downloads the wsusscn2.cab file if it doesn't exists in path parameter

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Path points to the folder and file e.g. C:\wsusscn2.cab

      .EXAMPLE
      Get-WsusCab -CabPath c:\wsusscn2.cab
      Describe what this call does

      .NOTES
      Author Jan Tiedemann 03.2019

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-WsusCab

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    [CmdletBinding()]
    param(
        [String]$CabPath
    )
    #$DownloadPath = $env:SystemDrive
    # Name of .cab file for the offline check
    $CabFile = 'wsusscn2.cab'
    # Url where to download latest wsusscn2.cab file
    $Uri = 'http://go.microsoft.com/fwlink/?LinkID=74689'
    # New WebClient object
    $client = New-Object System.Net.WebClient
    $client.Headers.Add("user-agent", "PowerShell")
  
    # Register Events DownloadFileCompleted and DownloadProgressChanged of System.Net.WebClient to be able to monitor download status and therefore progess bar.
    Register-ObjectEvent -InputObject $client -EventName DownloadFileCompleted -SourceIdentifier client.DownloadFileCompleted -Action {    
        $Global:isDownloaded = $True
    }
    Register-ObjectEvent -InputObject $client -EventName DownloadProgressChanged -SourceIdentifier client.DownloadProgressChanged -Action {
        $Global:Data = $event
    }

    If (((Test-Path -Path $CabPath) -eq $false)) {
        try {
            Write-Host "Please wait, downloading file: $CabFile"  
            #$client.DownloadFile($Uri, $CabPath)
            $client.DownloadFileAsync($Uri, $CabPath)
            #Show downloading progressbar as long $isDownloaded is not TRUE
            While (-Not $isDownloaded) {
                $percent = $Global:Data.SourceArgs.ProgressPercentage
                $totalBytes = $Global:Data.SourceArgs.TotalBytesToReceive
                $receivedBytes = $Global:Data.SourceArgs.BytesReceived
                If ($null -ne $percent) {
                    Write-Progress -Activity ("Downloading {0} from {1}" -f $CabPath, $Uri) -Status ("{0} bytes \ {1} bytes" -f $receivedBytes, $totalBytes) -PercentComplete $percent
                }
            }
            Write-Progress -Activity ("Downloading {0} from {1}" -f $CabPath, $Uri) -Status ("{0} bytes \ {1} bytes" -f $receivedBytes, $totalBytes) -Completed
        }
        catch [System.Net.WebException], [System.IO.IOException] {
            Write-Host "Unable to download $CabFile from $Uri"
            Write-Host "Please download it manually from $Uri and place it in your SystemRoot normally drive c:"
        }
        finally {
            if (Get-EventSubscriber) {  
                Write-Host "Unrigister Events"
                Get-EventSubscriber -Force | Unregister-Event -Force 
            }
        }
        Write-Host "download of file: $CabFile completed."
    }
}


### Main ##
#Check is Powershell was opened with Admin privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {    
    Write-Host "This script needs to be run As Admin" -ForegroundColor Red
    Write-Host "Furthermore the User should be Admin on each Computer/Server from where you want to gather the WindowsUpdate status !" -ForegroundColor Yellow
    Break
}

if ($Servers_file) {
    $Servers = @(Get-Content -Path $Servers_file)
} 
elseif ($ComputerName) {
    $Servers = $ComputerName -split ","
}

foreach ($ComputerName in $Servers) {
    # No $PSBoundParameters in CASE...
    $parameters = @{
        ComputerName = $ComputerName
        CabPath      = $CabPath
    }
    if (![System.IO.File]::Exists($CabPath)) {
        # file with path $CabPath doesn't exist
        #Get-WsusCab
        try {
            Get-WsusCab -CabPath $CabPath
        }
        #try with Bits
        Catch {
            Write-Host $Error[0].Exception.Message
        }
    }

    if ($UpdateSearchFilter) {
        $parameters.Add('UpdateSearchFilter', $UpdateSearchFilter)
    }

    if ($Credential) {
        $parameters.Add('Credential', $Credential)
    }
  
    try {
        if ([System.IO.File]::Exists($CabPath)) {
            Get-MissingSecurityUpdates @parameters
        }
        else {
            Throw [System.IO.FileNotFoundException] "File $CabPath not found."
        }
    }
    Catch {
        #Write-Host $Error[0].Exception.Message
        Write-Error -Exception ([System.IO.FileNotFoundException]::new("Could not find CabFile: $CabPath")) -ErrorAction Stop
    }
}
