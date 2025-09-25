<#
.SYNOPSIS
    Evo LDAP Agent Installer Script

.DESCRIPTION
    This script installs, upgrades, or removes the Evo LDAP Agent on a Windows machine.
    It can be used interactively or in silent mode with command-line parameters.

.PARAMETER EnvironmentUrl
    The Evo environment URL (e.g. https://yourorg.evosecurity.com)

.PARAMETER EvoDirectory
    The Evo directory or organization name of the tenant

.PARAMETER AccessToken
    API access token from the Evo Admin portal

.PARAMETER Secret
    API secret from the Evo Admin portal

.NOTES
    Requires administrator privileges unless run in interactive mode
#>

[CmdletBinding(DefaultParameterSetName='CommandLineConfig')]
param(
    [Parameter(ParameterSetName='JsonConfig')]
    [string] $Json,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $EnvironmentUrl,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $EvoDirectory,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $AccessToken,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $Secret,

    [Parameter(ParameterSetName='CommandLineConfig', HelpMessage='Multiple groups should be separated by a semicolon (;)')]
    [string] $SyncSecurityGroup,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] $UpdateInterval,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[bool]] $DisableUpdate,

    [Parameter(ParameterSetName='CommandLineConfig', HelpMessage='Leave blank to download latest. Otherwise path to MSI or zip file to install')]
    [string] $MSIPath,

    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig', DontShow=$true)]
    [hashtable] $Dictionary,
	
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [switch] $Beta,

    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Remove,

    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [switch] $Upgrade,

    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Interactive,

    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Log,

    [Parameter(ParameterSetName='HelpSet')]
    [switch] $Help

)

function Show-Help {
    @"
Evo LDAP Agent Installer
----------------------------------

This script installs, upgrades, or removes the Evo LDAP Agent.

Usage Examples:
---------------
  Install:
    .\InstallLdapAgent.ps1 -EnvironmentUrl "https://myorg.evosecurity.com" -EvoDirectory "MyOrg" -AccessToken "abc123" -Secret "xyz789" -SyncSecurityGroup "EvoSyncGroup"

  Install with logging and upgrade (uses existing settings):
    .\InstallLdapAgent.ps1 -Upgrade -Log

  Remove:
    .\InstallLdapAgent.ps1 -Remove -Interactive -Log

  Install from file:
    .\InstallLdapAgent.ps1 -EnvironmentUrl "..." -EvoDirectory "..." -AccessToken "..." -Secret "..." -SyncSecurityGroup "..." -MSIPath ".\ldapagent.zip"

  Help:
    .\InstallLdapAgent.ps1 -Help

Parameters:
-----------
  -EnvironmentUrl         Evo environment URL
  -EvoDirectory           Organization/tenant name
  -AccessToken            API token
  -Secret                 API secret
  -SyncSecurityGroup      Security group that the agent uses membership to sync AD users to Evo
  -UpdateInterval         Interval in minutes where agent syncs AD users
  -DisableUpdate          Optional flag to disable auto updates (defaults off or value of previous install)
  -MSIPath                Optional .msi or .zip file path
  -Upgrade                Validate version is newer before installing
  -Remove                 Uninstall agent
  -Interactive            Show UI for install/uninstall
  -Log                    Enable installer logging
  -Beta                   Use beta release
  -Help                   Show this message
  -Json                   (Legacy) Accept a JSON blob or path to a config file

Notes:
------
  - Requires elevation (admin) unless using -Interactive
  - You can also pass a legacy JSON config via -Json
  - For a new install, the only required values are -EnvironmentUrl, -EvoDirectory, -AccessToken, and -Secret (or those values in the -Json payload)
  - For an upgrade, the installer will inherit all the values from the previous install unless specified otherwise
"@ | Write-Host
    exit
}

if ($args -contains "--help" -or $args -contains "-help" -or $args -contains "/?" -or $args -contains "?" -or $args -contains "-?" -or $args -contains "/help") {
    Show-Help
}

if ($Help) {
    Show-Help
}

function IsRunningAsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function GetInstalledDisplayNames()
{
    return "Evo LDAPS Agent"
}

function GetInstalledSoftware($DisplayNames)
{
    foreach ($DisplayName in $DisplayNames) {
        $softwareKeys = Get-ChildItem hklm:\software\microsoft\windows\currentversion\uninstall | 
        Where-Object { $_.GetValue("DisplayName") -and $_.GetValue("DisplayName") -eq $DisplayName }

        if (-not $softwareKeys) {
            continue
        }

        if ($softwareKeys.Count -eq 1) {
            return $softwareKeys
        }

        Write-Verbose "Multiple entries found for $DisplayName`: $($softwareKeys.PSChildName)"

        $softwareKey = $softwareKeys | Where-Object { $_.PSChildName.StartsWith("{") } | Select-Object -First 1
        if ($softwareKey) {
            return $softwareKey
        }

        return $softwareKeys[0]
    }
    return $null
}

function GetBaseUrlAndInfoUrl {
    [CmdletBinding()]
    param (
        [switch] $Beta
    )

    $mid = if ($Beta) { 'beta' } else { 'release' }

    $BaseUrl = "https://download.evosecurity.com/$mid/ldapagent/"
    $LatestInfoUrl = $BaseUrl + "ldap-agent-latest-info.json" 

    return $BaseUrl, $LatestInfoUrl
}

function GetLatestInfo {
    [CmdletBinding()]
    param(
        [string] $LatestInfoUrl
    )

    $rawInfo = Invoke-RestMethod -uri $LatestInfoUrl -UseBasicParsing -Headers @{"Cache-Control"="no-cache"}
    Write-Verbose "Processor Architecture: $env:PROCESSOR_ARCHITECTURE"
    Write-Verbose "RawInfo: $rawInfo"

    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        Write-Verbose "ARM64 architecture detected"
        $latestInfo = [PSCustomObject] @{
            version = $rawInfo.version
            checksum = $rawInfo.architectures.arm64.checksum
            name = $rawInfo.architectures.arm64.name
        }
    }
    elseif ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        Write-Verbose "x64 architecture detected"
        $infoRoot = if ($rawInfo.architectures.X64) {$rawInfo.architectures.X64} else {$rawInfo}
        $latestInfo = [PSCustomObject] @{
            version = $rawInfo.version
            checksum = $infoRoot.checksum
            name = $infoRoot.name
        }
    }
    else {
        throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    }

    Write-Verbose "LatestInfo: $latestInfo"
    return $latestInfo
}

function GetTempMsiFrom-ByteArray {
    [CmdletBinding()]
    param(
        [byte[]] $bytes
    )

    Add-Type -Assembly 'System.IO.Compression'

    try{
        $memStream = [IO.MemoryStream]::new($bytes)
        
        try {
            $zipArchive = [System.IO.Compression.ZipArchive]::new($memStream, [System.IO.Compression.ZipArchiveMode]::Read)
            if ($zipArchive.Entries.Count -eq 1 -and $zipArchive.Entries[0].Name.ToLower().EndsWith(".msi")) {
                try {
                    $msiInStream = $zipArchive.Entries[0].Open()
                    try {
                        $msiOutPath = Join-Path $env:Temp $zipArchive.Entries[0].Name
                        $msiOutStream = [System.IO.File]::OpenWrite($msiOutPath)
                        $buffer = [byte[]]::new(32768)
                        $bytesRead = 0
                        while (0 -ne ($bytesRead = $msiInStream.Read($buffer, 0, $buffer.length))){
                            $msiOutStream.Write($buffer, 0, $bytesRead)
                        }
                        
                        return $msiOutPath # if everything successfull, this is the return of the function
                    }
                    catch {
                        if ($msiOutStream) {
                            $msiOutStream.Dispose() # has to be closed to delete it
                            $msiOutStream = $null # set to null here so it doesn't try again in finally
                            if ($msiOutPath -and (Test-Path $msiOutPath)){
                                Remove-Item $msiOutPath
                            }
                        }
                        throw
                    }
                    finally{
                        if ($msiOutStream) {
                            $msiOutStream.Dispose()
                        }
                    }
                }
                finally{
                    if ($msiInStream) {
                        $msiInStream.Dispose()
                    }
                }
            }
        }
        finally {
            if ($zipArchive) {
                $zipArchive.Dispose()
            }
        }
    }
    finally{
        if ($memStream){ 
            $memStream.Dispose()
        }
    }
}

function GetTempMsiFrom-Uri {
    [CmdletBinding()]
    param (
        [string] $uri,
        [string] $CheckSum
    )

    $GoodUri = [uri]::IsWellFormedUriString($uri, 'Absolute') -and ([uri] $uri).Scheme -in 'http', 'https'
    if (-not $GoodUri) {
        throw "Not a valid URI: $uri"
    }
    if (-not ($uri.ToLower().EndsWith(".zip"))) {
        throw "GetTempMsiFrom-Uri only supports zip archives."
    }

    # not wrapped in try/catch/finally because $WebContent doesn't have Dispose() method
    $WebContent = Invoke-WebRequest -uri $uri -UseBasicParsing -Headers @{"Cache-Control"="no-cache"}
    
    if ($CheckSum){
        Write-Verbose "Going to perform checksum"
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash($WebContent.Content)
        $hashString = [System.BitConverter]::ToString($hash).Replace("-","")
        if ($hashString -ne $CheckSum) {
            throw "Downloaded checksum is incorrect."
        }
    }
    return GetTempMsiFrom-ByteArray $WebContent.Content
}

function LdapAgentParamMapFromConfig {
    param(
        $config
    )

    $ParamMap = @{}

    if ($config.EnvironmentUrl) {
        $EnvUrl = $config.EnvironmentUrl.Trim("/ ")  # cleans up environment url
        $ParamMap["ENVIRONMENTURL"] = $EnvUrl
    }

    $ParamMap["DIRECTORY"] = $config.EvoDirectory
    $ParamMap["SECRET"] = $config.Secret
    $ParamMap["ACCESSTOKEN"] = $config.AccessToken
    $ParamMap["GROUPNAMES"] = $config.SyncSecurityGroup
    $UpdateInterval = $config.UpdateInterval
    if ($UpdateInterval -ne $null) {
        if ($UpdateInterval -is [int] -and $UpdateInterval -gt 0) {
            $ParamMap["UPDATEINTERVAL"] = "#$UpdateInterval"
        }

        if (-not ($ParamMap.Keys -contains "UPDATEINTERVAL")) {
            throw "UpdateInterval must be an integer greater than zero."
        }
    }

    $DisableUpdate = $Config.DisableUpdate
    switch  ($DisableUpdate) {
        {$_ -in ($false, 0)} { $ParamMap["DISABLE_UPDATE"] = "0" }
        {$_ -in ($true, 1)} { $ParamMap["DISABLE_UPDATE"] = "1" }
    }

    return $ParamMap
}

function GetJsonRawContent {
    [CmdletBinding()]
    param (
        [string] $JsonConfig
    )
	
    $JsonConfig = $JsonConfig.Trim(" `r`n") # trim all leading/trailing spaces and CR/LF
    Write-Verbose "Trimmed `$JsonConfig: $JsonConfig"
    if ($JsonConfig.StartsWith('{') -and $JsonConfig.EndsWith('}')) {
        $JsonBlob = $true # not a config file, but passed on command line
    }

    if (-not $JsonBlob) {
        $rp = Resolve-Path $JsonConfig -ErrorAction Stop
        $fi = [IO.FileInfo] $rp.ProviderPath
        if (-not $fi.Exists) { throw "Config file does not exist $fi" }
    
        $rawContent = (Get-Content $fi.FullName -Encoding UTF8 -Raw)
    }
    else {
        $rawContent = $JsonConfig
    }
	return $rawContent
}

function ParamMapFromJson {
    [CmdletBinding()]
    param (
        [string] $JsonConfig
    )
    
    $ParamMap = @{}
    if (-not $JsonConfig) {
        return $ParamMap
    }

	$rawContent = GetJsonRawContent $JsonConfig

    Write-Verbose "RawContent: $rawContent"
    try {
        $config = ConvertFrom-Json $rawContent
    }
    catch {
        throw
    }
    Write-Verbose $config

    $ParamMap = LdapAgentParamMapFromConfig $config
    
    if ($config.MSIPath) {
        $ParamMap["MSIPath"] = $config.MSIPath
    }

    # trim string values in ParamMap
    foreach ($key in $ParamMap.Keys.Clone()) {
        $val = $ParamMap[$key]
        if ($val -and $val.GetType() -eq [string]) {
            $ParamMap[$key] = $val.Trim()
        }
    }
    
    return $ParamMap
}

function MakeMsiExecArgs {
    [CmdletBinding()]
    param (
        [Hashtable] $ParamMap
    )

    $msiArgs = @()
    if ($ParamMap) {
        foreach ($key in $ParamMap.Keys) {
            if ($key -ne "MSIPath") {
                $value = $ParamMap[$key]
                if (-not [string]::IsNullOrEmpty($value)) {
                    $msiArgs += "$key=`"$value`""
                }
            }
        }
    }

    if ($msiArgs.Count -gt 0) {
        return $msiArgs
    }

    # PowerShell returns $null if the array is empty, this is the idiosyncratic way
    # of avoiding that error/"feature"
    return , $msiArgs
}

function InstallMsi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string] $MsiPath,
        [array] $MsiParameters,
        [bool] $Interactive,
        [string] $LogFileName
    )

    $localParams = $MsiParameters.Clone()
    $localParams += "/i"
    $localParams += "`"$MsiPath`""
    if (-not $Interactive) {
        $localParams += "/qn"
    }

    if (-not [string]::IsNullOrEmpty($LogFileName)){
        $localParams += "/log"
        $localParams += $LogFileName
    }

    Write-Verbose "Local params: $localParams"
    $process = Start-Process 'msiexec.exe' -ArgumentList $localParams -Wait -Passthru
    if ($process.ExitCode -ne 0) {
        throw "Installer process error, exit code: $($process.ExitCode)"
    }
}

function CompareVersions {
    [CmdletBinding()]
    param(
        [string] $firstString,
        [string] $secondString
    )

    Write-Verbose "Version compare, First=$firstString, Second=$secondString"

    $zeros = @(0,0,0,0)
    $first = $firstString.Split(".")[0..3]
    $second = $secondString.Split(".")[0..3]

    if ($first.Count -eq 0 -or $second.Count -eq 0) {
        throw "Improperly formatted version strings, First=$firstString, Second=$secondString"
    }

    if ($first.Count -lt $second.Count) {
        $first += $zeros[(1..($second.Count - $first.Count))]
    }
    elseif ($second.Count -lt $first.Count) {
        $second += $zeros[(1..($first.Count - $second.Count))]
    }

    for ($i = 0; $i -lt $first.Count; ++$i) {
        $fint = [int] $first[$i]
        $sint = [int] $second[$i]

        if ($fint -gt $sint) {
            return -1
        }
        if ($fint -lt $sint){
            return 1
        }
    }

    return 0
}

function GetInstalledVersion() {
    $DisplayNames = GetInstalledDisplayNames

    $InstalledSoftwareKey = GetInstalledSoftware $DisplayNames

    if (-not $InstalledSoftwareKey) {
        return $null
    }

    $InstalledVersion = $InstalledSoftwareKey.GetValue("DisplayVersion")
    return $InstalledVersion
}

function VerifyVersionForUpgrade {
    [CmdletBinding()]
    param(
        $VersionToTest # from website
    )

    $InstalledVersion = GetInstalledVersion

    if (-not $InstalledVersion) {
        throw "Cannot upgrade because software is not installed"
    }

    $Comparison = CompareVersions $InstalledVersion $VersionToTest

    if ($comparison -eq -1) {
        throw "The currently installed version is more recent than that downloaded. Cannot ""upgrade"" it."
    }

    if ($comparison -eq 0) {
        throw "The currently installed version is already at the most recent. Not upgrading."
    }

}

function GetLogFileName {
    param(
       [bool] $Upgrading
    )

    $Base = "EvoLdapAgent"
    $suffix = if (-not $Upgrading) { "install" } else {"upgrade"}
    Join-Path $Env:TEMP "$($Base)_$($suffix).log"
}

function DoRemoveAgent()
{
    param(
        [bool] $Interactive,
        [bool] $Log
    )

    $DisplayNames = GetInstalledDisplayNames

    Write-Verbose "DisplayNames: $DisplayNames"

    $softwareKey = GetInstalledSoftware $DisplayNames

    if (-not $softwareKey) {
        return "Software not installed: $DisplayNames"
    }

    # our friend advanced installer creates two entries ... muchas gracias por nada
    if ($softwareKey -is [array]) {
        $softwareKey = $softwareKey[0]
    }
    Write-Verbose "SoftwareKey: $softwareKey"

    $localParams = @("/X", "`"$($softwareKey.PSChildName)`"")
    if (-not $Interactive) {
        $localParams += "/qn"
    }

    if ($Log) {
        $LogFileName = Join-Path $Env:TEMP "EvoLdapAgent_remove.log"
        $localParams += "/log"
        $localParams += $LogFileName
    }

    Write-Verbose "local params: $localParams"
    Start-Process "msiexec.exe" -ArgumentList $localParams -Wait
}

function Get-MSIVersion {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MSIPath
    )
    
    try {
        # Create Windows Installer object
        $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        
        # Open the MSI database
        $database = $windowsInstaller.OpenDatabase($MSIPath, 0)
        
        # Query the Property table for ProductVersion
        $view = $database.OpenView("SELECT Value FROM Property WHERE Property = 'ProductVersion'")
        $view.Execute()
        
        # Fetch the result
        $record = $view.Fetch()
        if ($record) {
            $version = $record.StringData(1)
            return $version
        } else {
            throw "Could not find ProductVersion property"
        }
    }
    catch {
        Write-Error "Error reading MSI version: $_"
        return $null
    }
    finally {
        # Clean up COM objects
        if ($view) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null }
        if ($database) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null }
        if ($windowsInstaller) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null }
    }
}

####################  Execution starts here  ####################

if (-not $Interactive -and -not (IsRunningAsAdministrator)) {
    throw "Error: this script must be run from an elevated shell when run non-interactively because the installer components need elevation to succeed"
}

if ($Remove) {
    return DoRemoveAgent $Interactive $Log
}

$InstalledVersion = GetInstalledVersion
Write-Verbose "Installed version: $InstalledVersion"

if ($Upgrade) {
    if (-not $InstalledVersion) {
        throw "Cannot upgrade because software is not installed"
    }
}

if (-not $Json) {
    Write-Verbose "Installing Evo LDAP Agent..."
    # Write-Verbose "Parameters: EnvironmentUrl=$EnvironmentUrl; EvoDirectory=$EvoDirectory; Secret=$Secret; AccessToken=$AccessToken"
    $MapForJson = @{}

    if ($EnvironmentUrl) {
        $MapForJson += @{ EnvironmentUrl = $EnvironmentUrl}
    }
    if ($EvoDirectory) {
        $MapForJson += @{ EvoDirectory = $EvoDirectory}
    }
    if ($Secret) {
        $MapForJson += @{ Secret = $Secret}
    }
    if ($AccessToken) {
        $MapForJson += @{ AccessToken = $AccessToken}
    }
    if ($SyncSecurityGroup) {
        $MapForJson += @{ SyncSecurityGroup = $SyncSecurityGroup }
    }
    if ($UpdateInterval) {
        $MapForJson += @{ UpdateInterval = $UpdateInterval }
    }
    if ($null -ne $DisableUpdate) {
        $MapForJson += @{ DisableUpdate = $DisableUpdate}
    }
    if ($MSIPath) {
        $MapForJson += @{ MSIPath = $MSIPath}
    }

    $Json = ConvertTo-Json $MapForJson

    Write-Verbose "Json:`n$Json"
}

$ParamMap = ParamMapFromJson $Json

if ($Dictionary) {
    foreach ($key in $Dictionary.Keys) {
        $ParamMap[$key] = $Dictionary[$key]
    }
}

Write-Verbose "ParamMap: $($ParamMap.Keys)"

$MSIParams = MakeMsiExecArgs $ParamMap

$BaseUrl, $InfoUrl = GetBaseUrlAndInfoUrl -beta:$Beta

if (-not $ParamMap.MSIPath) { ### we have to download the file ...

    $LatestInfo = GetLatestInfo $InfoUrl
    if ($Upgrade){
        VerifyVersionForUpgrade $LatestInfo.version
    }

    Write-Verbose "ParamMap MSIPath is empty, downloading latest"
    $LatestUrl = $BaseUrl + $LatestInfo.Name
    Write-Verbose "Downloading latest URL: $LatestUrl"

    Write-Verbose "Checksum=$($LatestInfo.Checksum)"
    $TempMsiFile = GetTempMsiFrom-Uri $LatestUrl $LatestInfo.checksum # this creates a temp file which we will cleanup later
    $MSIPath = $TempMsiFile
} else {
    if (-not (Test-Path $ParamMap.MSIPath)) {
        throw "MSI path does not exist: $($ParamMap.MSIPath)"
    } else {
        if ($ParamMap.MSIPath.ToLower().EndsWith(".msi")) {
            $MSIPath = $ParamMap.MSIPath
        }
        elseif ($ParamMap.MSIPath.ToLower().EndsWith(".zip")) {
            $msiBytes = [IO.File]::ReadAllBytes($ParamMap.MSIPath)
            $TempMsiFile = GetTempMsiFrom-ByteArray $msiBytes
            $MSIPath = $TempMsiFile
        }
        else {
            throw "Invalid file format: $($ParamMap.MSIPath). Must be ZIP or MSI format."
        }
        Write-Verbose "Setting MSIPath to file in JSON config file: $MsiPath"

        $MSIVersion = Get-MSIVersion -MSIPath $MSIPath

        if ($InstalledVersion) {
            if (-not $MSIVersion) {
                throw "Cannot upgrade because MSI version cannot be determined"
            }

            $Comparison = CompareVersions $InstalledVersion $MSIVersion
            if ($Comparison -eq -1) {
                throw "The currently installed version is more recent than that specified in MSIPath file. Cannot ""upgrade"" it."
            }
            if ($Comparison -eq 0) {
                throw "The currently installed version is already at the version specified in MSIPath file. Not upgrading."
            }
        }
    }
}

try {
    $DebugFlag = if ($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent) {$true} else {$false}
    Write-Output "MSI path for installer: $MSIPath"
    Write-Output "InstallerParams: $($MSIParams | Where-Object {$DebugFlag -or (-not $_.StartsWith('APIKEY') -and -not $_.StartsWith('SECRET'))} )"

    if ($DebugFlag) {
        return "Quitting because Debug flag was used"
    }
    
    $InstallMSIArgs = @{
        MsiPath = $MSIPath
        MsiParameters = $MSIParams
        Interactive = $Interactive
        LogFileName = if ($Log) { GetLogFileName $Upgrade } else { "" }
    }
    InstallMSI @InstallMSIArgs
	
}
finally {
    if ($TempMsiFile -and (Test-Path $TempMsiFile)) {
        Write-Verbose "Deleting $TempMsiFile"
        Remove-Item $TempMsiFile
    }
}
