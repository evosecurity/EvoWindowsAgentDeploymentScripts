<#
.SYNOPSIS
    Evo Windows Agent Installer Script

.DESCRIPTION
    This script installs, upgrades, or removes the Evo Windows Agent on a Windows machine.
    It can be used interactively or in silent mode with command-line parameters.

.PARAMETER DeploymentToken
    The deployment token from the Evo Admin portal

.PARAMETER EnvironmentUrl
    The Evo environment URL (e.g. https://yourorg.evosecurity.com)

.PARAMETER EvoDirectory
    Your Evo directory or organization name

.PARAMETER AccessToken
    API access token from the Evo Admin portal

.PARAMETER Secret
    API secret from the Evo Admin portal

.PARAMETER CredentialMode
    Login mode. One of: SecureLogin, ElevatedLogin, SecureAndElevatedLogin
    The installer defaults to SecureAndElevatedLogin on a new installation, or defaults to the previous value on an upgrade

.PARAMETER OnlyEvoLoginCredential
    Set to $true to make Evo the sole credential provider

.PARAMETER FailSafeUser
    Optional username to use as a fallback if Evo login fails

.PARAMETER MFATimeOut
    Optional grace period to not require MFA for an unlock (in minutes from previous MFA prompt)

.PARAMETER RememberLastUserName
    Optional flag to remember the last username used

.PARAMETER DisableUpdate
    Optional flag to disable auto updates

.PARAMETER JitMode
    Optional flag to enable Just-In-Time admin accounts

.PARAMETER EndUserElevation
    Optional flag to enable end-user elevation

.PARAMETER UserAdminEscalation
    Optional flag to prompt admins with the end-user elevation prompt instead of the standard UAC prompt

.PARAMETER CustomPrompt
	Optional path to a custom login prompt label

.PARAMETER CustomImage
	Optional path to a custom login prompt image can be URL or local file path. Must be PNG, JPEG, or Bitmap.
    Recommended size is 192x192 with no transparency

.PARAMETER NoElevatedRDP
    Optional flag to disable elevation for RDP sessions when Evo is the sole login agent

.PARAMETER UACExtension
    Optional setting to enable UAC extension (0=disabled, 1=enabled, other credential providers available in UAC dialog, 2=enabled, Evo exclusive in UAC dialog )

.PARAMETER DisableEvoLogin
    Optional setting to disable the Evo credential on the login screen

.PARAMETER DisableEvoUac
    Optional setting to disable the Evo credential in the UAC dialog

.PARAMETER UnlimitedExtendedUacSession
    Optional setting to enable unlimited extended UAC session

.PARAMETER PersistentRequest
    Optional setting to enable persistent elevation request notifications instead of having a 10 second timeout

.PARAMETER RMM
    Optional setting to enable RMM (Remote Monitoring and Management) functionality. Only Ninja deployment token retrieval for now. 

.PARAMETER MSIPath
    Optional path to a .msi or .zip file. If omitted, the latest version is downloaded.
    Cannot be used together with InstallerPath. Deprecated in favor of InstallerPath.

.PARAMETER InstallerPath
    Optional path to a .msi, .exe, or .zip file (zip must contain a single .msi or .exe).
    Cannot be used together with MSIPath.

.PARAMETER Upgrade
    If specified, will only install a newer version over a previously installed version

.PARAMETER Remove
    Uninstalls the Evo Windows Agent

.PARAMETER Interactive
    Runs the installer in UI mode (non-silent)

.PARAMETER Log
    Enables logging of the installation/removal process

.PARAMETER Beta
    Use the beta version of the installer from Evo s servers

.PARAMETER Help
    Displays usage information

.EXAMPLE
    .\InstallEvoAgent.ps1 -EnvironmentUrl "https://..." -EvoDirectory "..." -AccessToken "..." -Secret "..." -CredentialMode "SecureLogin" -Upgrade -Log

.NOTES
    Requires administrator privileges unless run in interactive mode
#>

[CmdletBinding(DefaultParameterSetName='CommandLineConfig')]
param(
    [Parameter(ParameterSetName='JsonConfig')]
    [string] $Json,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [string] $DeploymentToken,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $EnvironmentUrl,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $EvoDirectory,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $AccessToken,

    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $Secret,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [string] $FailSafeUser,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[uint32]] $MFATimeOut,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [ValidateSet('10', '90', '100', 'SecureLogin', 'ElevatedLogin', 'SecureAndElevatedLogin')]
    [string] $CredentialMode,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [ValidateSet(0, 1, $false, $true)] $OnlyEvoLoginCredential,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [switch] $NoElevatedRDP,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[bool]] $DisableUpdate,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $JitMode,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $EndUserElevation,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $UserAdminEscalation,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $RememberLastUserName,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1, 2)] $UACExtension,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $DisableEvoLogin,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $DisableEvoUac,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $UnlimitedExtendedUacSession,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Nullable[int]] [ValidateSet(0, 1)] $PersistentRequest,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [string] $RMM,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig', HelpMessage='Leave blank to download latest. Otherwise path to MSI or zip file to install')]
    [string] $MSIPath,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig', HelpMessage='Path to MSI, EXE, or zip file to install. Cannot be used with MSIPath')]
    [string] $InstallerPath,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig', DontShow=$true)]
    [hashtable] $Dictionary,
	
    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
	[string] $CustomPrompt,
	
    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
	[string] $CustomImage,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [switch] $Beta,

    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Remove,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [switch] $Upgrade,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Interactive,

    [Parameter(ParameterSetName='DeploymentTokenConfig')]
    [Parameter(ParameterSetName='JsonConfig')]
    [Parameter(ParameterSetName='CommandLineConfig')]
    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Log,

    [Parameter(ParameterSetName='HelpSet')]
    [switch] $Help
)

function Show-Help {
    @"
Evo Windows Agent Installer
----------------------------------

This script installs, upgrades, or removes the Evo Windows Agent.

Usage Examples:
---------------
  Install with deployment token (preferred since version 2.5):
    .\InstallEvoAgent.ps1 -DeploymentToken "abc123"

  Install using old parameters:
    .\InstallEvoAgent.ps1 -EnvironmentUrl "https://myorg.evosecurity.com" -EvoDirectory "MyOrg" -AccessToken "abc123" -Secret "xyz789"

  Install with logging and upgrade (uses existing settings):
    .\InstallEvoAgent.ps1 -Upgrade -Log

  Remove:
    .\InstallEvoAgent.ps1 -Remove -Interactive -Log

  Install from MSI or zip file (legacy):
    .\InstallEvoAgent.ps1 -EnvironmentUrl "..." -EvoDirectory "..." -AccessToken "..." -Secret "..." -MSIPath ".\agent.zip"

  Install from MSI, EXE, or zip file:
    .\InstallEvoAgent.ps1 -EnvironmentUrl "..." -EvoDirectory "..." -AccessToken "..." -Secret "..." -InstallerPath ".\agent.exe"

  Help:
    .\InstallEvoAgent.ps1 -Help

Parameters:
-----------
  -DeploymentToken        Deployment token (preferred method since version 2.5)
  -EnvironmentUrl         Evo environment URL
  -EvoDirectory           Organization/tenant name
  -AccessToken            API token
  -Secret                 API secret
  -FailSafeUser           Optional username to use as a fallback if Evo login fails
  -MFATimeOut             Optional grace period to not require MFA for an unlock (in minutes from previous MFA prompt)
  -CredentialMode         SecureLogin | ElevatedLogin | SecureAndElevatedLogin (defaults to SecureAndElevatedLogin or value of previous install)
  -OnlyEvoLoginCredential Use Evo as sole credential provider (defaults to false or value of previous install)
  -RememberLastUserName   Optional flag to remember the last username used (defaults on or value of previous install)
  -DisableUpdate          Optional flag to disable auto updates (defaults off or value of previous install)
  -JitMode                Optional flag to enable Just-In-Time admin accounts (defaults off or value of previous install)
  -EndUserElevation       Optional flag to enable end-user elevation (defaults off or value of previous install)
  -UserAdminEscalation    Optional flag to prompt admins with the end-user elevation prompt instead of the standard UAC prompt (defaults off or value of previous install)
  -CustomPrompt           Optional path to a custom login prompt label
  -CustomImage            Optional path to a custom login prompt image
  -NoElevatedRDP          Optional flag to disable elevation for RDP sessions when Evo is the sole login agent (defaults on or value of previous install)
  -UACExtension           Optional setting to enable UAC extension (0=disabled, 1=enabled, other credential providers available in UAC dialog, 2=enabled, Evo exclusive in UAC dialog ) (defaults disabled or value of previous install)
  -DisableEvoLogin        Optional setting to disable the Evo credential on the login screen (defaults off or value of previous install, minimum supported agent = 2.4)
  -DisableEvoUac          Optional setting to disable the Evo credential in the UAC dialog (defaults off or value of previous install, minimum supported agent = 2.4)
  -UnlimitedExtendedUacSession Optional setting to enable unlimited extended UAC session (defaults off or value of previous install, minimum supported agent = 2.4)
  -PersistentRequest      Optional setting to enable persistent elevation request notifications instead of having a 10 second timeout (defaults off or value of previous install, minimum supported agent = 2.4)
  -RMM                    Optional setting to enable RMM (Remote Monitoring and Management) functionality -- only Ninja deployment token retrieval for now
  -MSIPath                Optional .msi or .zip file path (legacy; mutually exclusive with InstallerPath)
  -InstallerPath          Optional .msi, .exe, or .zip file path (mutually exclusive with MSIPath)
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
  - For a new install, the only required values are -DeploymentToken, or if not using Deployment Token then -EnvironmentUrl, -EvoDirectory, -AccessToken, and -Secret (or those values in the -Json payload)
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

function Start-InstallerProcess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string] $FilePath,
        $ArgumentList
    )

    $startParams = @{
        FilePath = $FilePath
        Wait = $true
        PassThru = $true
    }
    if ($ArgumentList) {
        $startParams['ArgumentList'] = $ArgumentList
    }
    if (-not (IsRunningAsAdministrator)) {
        $startParams['Verb'] = 'RunAs'
    }

    Write-Verbose "Starting installer: FilePath=$FilePath Verb=$($startParams.Verb) ArgumentList=$ArgumentList"
    try {
        return Start-Process @startParams
    }
    catch {
        if ($_.Exception.Message -match 'canceled|cancelled|1223') {
            throw "Installation was cancelled or elevation was denied."
        }
        throw
    }
}

function GetInstalledDisplayName()
{
    return "Evo Agent"
}

function GetInstalledDisplayNames()
{
    return "Evo Agent","Evo Secure Login"
}

# For now only Ninja is supported, and only for the DeploymentToken property
function Get-DynamicToken {
    param (
        [string]$Token,
		[string]$RMM
    )
	
	if ([string]::IsNullOrWhiteSpace($RMM)) {
		return $Token
	}
	
	if ([string]::IsNullOrWhiteSpace($Token)) {
		Write-Error "An RMM was specified ($RMM) but the required token property was not provided"
		exit 1
	}
	
	switch ($RMM.ToLower()) {
		"ninja" {
			Write-Host "Action: Fetching '$Token' from Ninja RMM..." -ForegroundColor Cyan
			try {
                # Ensure the command exists to avoid a "CommandNotFound" red block
                if (-not (Get-Command "Ninja-Property-Get" -ErrorAction SilentlyContinue)) {
                    throw "Ninja-Property-Get command not found. Is the Ninja Agent installed?"
                }
				
				$Result = (Ninja-Property-Get $Token | Out-String).Trim()
				if (-not $Result) { throw "Property is empty." }
				return $Result
			}
			catch {
				Write-Error "Failed to retrieve from Ninja: $_"
				exit 1
			}
		}
		default {
			Write-Error "RMM $RMM is not currently supported by this script."
			exit 1
		}
	}
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

    $BaseUpdateUrl = if ($env:EvoBaseUpdateUrl) {$env:EvoBaseUpdateUrl} else { 'https://download.evosecurity.com' }

    $BaseUrl = "$BaseUpdateUrl/$mid/credpro/"
    $LatestInfoUrl = $BaseUrl + "credential-provider-latest-info.json" 

    return $BaseUrl, $LatestInfoUrl
}

function GetLatestInfo {
    [CmdletBinding()]
    param(
        [string] $LatestInfoUrl
    )

    Write-Verbose "LatestInfoUrl: $LatestInfoUrl"
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
        $latestInfo = [PSCustomObject] @{
            version = $rawInfo.version
            checksum = $rawInfo.architectures.x64.checksum
            name = $rawInfo.architectures.x64.name
        }
    }
    else {
        throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    }

    Write-Verbose "LatestInfo: $latestInfo"
    return $latestInfo
}

function GetTempInstallerFrom-ByteArray {
    [CmdletBinding()]
    param(
        [byte[]] $bytes
    )

    Add-Type -Assembly 'System.IO.Compression'

    try{
        $memStream = [IO.MemoryStream]::new($bytes)
        
        try {
            $zipArchive = [System.IO.Compression.ZipArchive]::new($memStream, [System.IO.Compression.ZipArchiveMode]::Read)
            if ($zipArchive.Entries.Count -eq 1) {
                $entryName = $zipArchive.Entries[0].Name.ToLower()
                if ($entryName.EndsWith(".msi") -or $entryName.EndsWith(".exe")) {
                try {
                    $installerInStream = $zipArchive.Entries[0].Open()
                    try {
                        $installerOutPath = Join-Path $env:Temp $zipArchive.Entries[0].Name
                        $installerOutStream = [System.IO.File]::OpenWrite($installerOutPath)
                        $buffer = [byte[]]::new(32768)
                        $bytesRead = 0
                        while (0 -ne ($bytesRead = $installerInStream.Read($buffer, 0, $buffer.length))){
                            $installerOutStream.Write($buffer, 0, $bytesRead)
                        }
                        
                        return $installerOutPath # if everything successfull, this is the return of the function
                    }
                    catch {
                        if ($installerOutStream) {
                            $installerOutStream.Dispose() # has to be closed to delete it
                            $installerOutStream = $null # set to null here so it doesn't try again in finally
                            if ($installerOutPath -and (Test-Path $installerOutPath)){
                                Remove-Item $installerOutPath
                            }
                        }
                        throw
                    }
                    finally{
                        if ($installerOutStream) {
                            $installerOutStream.Dispose()
                        }
                    }
                }
                finally{
                    if ($installerInStream) {
                        $installerInStream.Dispose()
                    }
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

    throw "Zip archive must contain a single .msi or .exe file."
}

function Resolve-LocalInstallerPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string] $Path,
        [Parameter(Mandatory=$true)][string] $ParameterName,
        [switch] $AllowExe
    )

    if (-not (Test-Path $Path)) {
        throw "$ParameterName path does not exist: $Path"
    }

    $lowerPath = $Path.ToLower()
    $tempFile = $null
    $resolvedPath = $null
    $useExe = $false

    if ($lowerPath.EndsWith(".msi")) {
        $resolvedPath = $Path
    }
    elseif ($AllowExe -and $lowerPath.EndsWith(".exe")) {
        $resolvedPath = $Path
        $useExe = $true
    }
    elseif ($lowerPath.EndsWith(".zip")) {
        $installerBytes = [IO.File]::ReadAllBytes($Path)
        $tempFile = GetTempInstallerFrom-ByteArray $installerBytes
        $resolvedPath = $tempFile
        $useExe = $resolvedPath.ToLower().EndsWith(".exe")
    }
    else {
        $allowedFormats = if ($AllowExe) { "MSI, EXE, or ZIP" } else { "ZIP or MSI" }
        throw "Invalid file format: $Path. Must be $allowedFormats format."
    }

    Write-Verbose "Resolved $ParameterName to: $resolvedPath"

    return @{
        ResolvedPath = $resolvedPath
        TempFile = $tempFile
        UseExeInstaller = $useExe
    }
}

function Test-LocalInstallerVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string] $LocalInstallerPath,
        [Parameter(Mandatory=$true)][string] $ParameterName,
        [string] $InstalledVersion,
        [bool] $UseExeInstaller = $false
    )

    if (-not $InstalledVersion) {
        return
    }

    if ($UseExeInstaller) {
        $InstallerVersion = Get-ExeVersion -ExePath $LocalInstallerPath
        if (-not $InstallerVersion) {
            throw "Cannot upgrade because EXE version cannot be determined"
        }
    }
    else {
        $InstallerVersion = Get-MSIVersion -MSIPath $LocalInstallerPath
        if (-not $InstallerVersion) {
            throw "Cannot upgrade because MSI version cannot be determined"
        }
    }

    $installerType = if ($UseExeInstaller) { 'EXE' } else { 'MSI' }
    Write-Verbose "Comparing installed version $InstalledVersion with $installerType version $InstallerVersion"

    $Comparison = CompareVersions $InstalledVersion $InstallerVersion
    if ($Comparison -eq -1) {
        throw "The currently installed version is more recent than that specified in $ParameterName file. Cannot ""upgrade"" it."
    }
    if ($Comparison -eq 0) {
        throw "The currently installed version is already at the version specified in $ParameterName file. Not upgrading."
    }
}

function GetTempInstallerFrom-Uri {
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
        throw "GetTempInstallerFrom-Uri only supports zip archives."
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
    return GetTempInstallerFrom-ByteArray $WebContent.Content
}

function CredProParamMapFromConfig {
    param(
        $config
    )

    $ParamMap = @{}

    if ($config.CredentialMode) {
        enum CredentialMode { 
            SecureLogin = 90 # is the default in the CredPro MSI if not specified
            ElevatedLogin = 10
            SecureAndElevatedLogin = 100
        }
        try {
            $CredentialMode = [CredentialMode] $config.CredentialMode # conversion can potentially throw
        }
        catch {
            throw # this way gives a better indication of where the problem is
        }
    }

    if ($config.DeploymentToken) {
        $ParamMap["DEPLOYMENT_TOKEN_VALUE"] = $config.DeploymentToken
    }

    if ($config.EnvironmentUrl) {
        $EnvUrl = $config.EnvironmentUrl.Trim("/ ")  # cleans up environment url
        $ParamMap["ENVIRONMENTURL"] = $EnvUrl
    }

    $ParamMap["DOMAIN"] = $config.EvoDirectory

    if ($config.MFATimeOut) { 
        $ParamMap["MFATIMEOUT"] = $config.MFATimeOut
    }
    
    if (-not [string]::IsNullOrEmpty($config.FailSafeUser)) {
        $ParamMap["FAILSAFEUSER"] = $config.FailSafeUser
    }

    $ParamMap["APIKEY"] = $config.Secret
    $ParamMap["ACCESSTOKEN"] = $config.AccessToken


    if ($CredentialMode) {
        $ParamMap["CREDENTIAL_MODE"] = [int] $CredentialMode
    }

    $flag = $config.OnlyEvoLoginCredential
    if ($null -eq $flag) {
        # we store it in the registry now ... however, a very old system may not have it
        $evo_login_only = (Get-ItemProperty 'HKLM:\software\EvoSecurity\EvoLogin-CP' -ErrorAction SilentlyContinue).evo_login_only
        if (0 -eq $evo_login_only) {
            $flag = $false
        }
        elseif (1 -eq $evo_login_only) {
            $flag = $true
        }
    }

    if ($flag -eq $true) {
        $ParamMap["SOLEPROVIDER"] = 1
    } elseif ($flag -eq $false) {
        $ParamMap["SOLEPROVIDER"] = 0
    } elseif ($flag -ne $null) {
        Write-Host "Invalid value in Json file for OnlyEvoLoginCredential. Installer will use default value, or original install value."
    }

    $NoElevatedRDP = $config.NoElevatedRDP
    if ($NoElevatedRDP -eq $false) {
        $ParamMap["NOELEVRDP"] = "0"
    } elseif ($NoElevatedRDP -eq $true) {
        $ParamMap["NOELEVRDP"] = "1"
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

    $ParamMap = CredProParamMapFromConfig $config
    
    if ($config.MSIPath) {
        $ParamMap["MSIPath"] = $config.MSIPath
    }

    if ($config.InstallerPath) {
        $ParamMap["InstallerPath"] = $config.InstallerPath
    }
    elseif ($config.EXEPath) {
        $ParamMap["InstallerPath"] = $config.EXEPath
    }

    if ($true -eq $config.DisableUpdate) {
        $ParamMap["DISABLE_UPDATE"] = 1
    }
    elseif ($false -eq $config.DisableUpdate) {
        $ParamMap["DISABLE_UPDATE"] = 0
    }

    if ($config.JitMode -eq 1) {
        $ParamMap["JITMODE"] = 1
    }
    elseif ($config.JitMode -eq 0) {
        $ParamMap["JITMODE"] = 0
    }

    if ($config.EndUserElevation -eq 1) {
        $ParamMap["ENDUSERELEVATION"] = 1
    }
    elseif ($config.EndUserElevation -eq 0) {
        $ParamMap["ENDUSERELEVATION"] = 0
    }

    if ($config.UserAdminEscalation -eq 1) {
        $ParamMap["USER_ADMIN_ESCALATION"] = 1
    }
    elseif ($config.UserAdminEscalation -eq 0) {
        $ParamMap["USER_ADMIN_ESCALATION"] = 0
    }

    if ($config.RememberLastUserName -eq 1) {
        $ParamMap["ENABLE_LAST_USERNAME"] = 1
    }
    elseif ($config.RememberLastUserName -eq 0) {
        $ParamMap["ENABLE_LAST_USERNAME"] = 0
    }

    if ($config.UACExtension -eq 0) {
        $ParamMap["UAC_EXTENSION"] = 0
    }
    elseif ($config.UACExtension -eq 1) {
        $ParamMap["UAC_EXTENSION"] = 1
    }
    elseif ($config.UACExtension -eq 2) {
        $ParamMap["UAC_EXTENSION"] = 2
    }

    if ($config.DisableEvoLogin -eq 1) {
        $ParamMap["DISABLE_EVO_LOGIN"] = 1
    }
    elseif ($config.DisableEvoLogin -eq 0) {
        $ParamMap["DISABLE_EVO_LOGIN"] = 0
    }

    if ($config.DisableEvoUac -eq 1) {
        $ParamMap["DISABLE_EVO_UAC"] = 1
    }
    elseif ($config.DisableEvoUac -eq 0) {
        $ParamMap["DISABLE_EVO_UAC"] = 0
    }

    if ($config.UnlimitedExtendedUacSession -eq 1) {
        $ParamMap["UNLIMITED_EXTENDED_UAC_SESSION"] = 1
    }
    elseif ($config.UnlimitedExtendedUacSession -eq 0) {
        $ParamMap["UNLIMITED_EXTENDED_UAC_SESSION"] = 0
    }

    if ($config.PersistentRequest -eq 1) {
        $ParamMap["PERSISTENT_REQUEST"] = 1
    }
    elseif ($config.PersistentRequest -eq 0) {
        $ParamMap["PERSISTENT_REQUEST"] = 0
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
            if ($key -notin @("MSIPath", "InstallerPath", "EXEPath")) {
                $value = $ParamMap[$key]
                if (-not [string]::IsNullOrEmpty($value)) {
                    $msiArgs += "$key=`"$value`""
                }
            }
        }
    }

    if ($msiArgs.Count -gt 0) {
        return @($msiArgs)
    }

    return @()
}

function InstallMsi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string] $MsiPath,
        [array] $MsiParameters,
        [bool] $Interactive,
        [string] $LogFileName
    )

    $argString = "/i `"$MsiPath`""
    if (-not $Interactive) {
        $argString += " /qn"
    }

    if (-not [string]::IsNullOrEmpty($LogFileName)){
        $argString += " /log `"$LogFileName`""
    }

    if ($MsiParameters) {
        foreach ($param in $MsiParameters) {
            if ($null -ne $param -and $param -match '\s') {
                $escaped = $param -replace '"', '\"'
                $argString += " `"$escaped`""
            }
            elseif ($null -ne $param) {
                $argString += " $param"
            }
        }
    }

    Write-Verbose "Local params: $argString"
    $process = Start-InstallerProcess -FilePath 'msiexec.exe' -ArgumentList $argString
    if ($process.ExitCode -ne 0) {
        throw "Installer process error, exit code: $($process.ExitCode)"
    }
}

function InstallExe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string] $ExePath,
        [array] $InstallerParameters,
        [bool] $Interactive,
        [string] $LogFileName
    )

    $argString = ''
    if (-not $Interactive) {
        $argString += '/exenoui /qn'
    }

    if (-not [string]::IsNullOrEmpty($LogFileName)){
        $argString += " /exelog `"$LogFileName`""
    }

    if ($InstallerParameters) {
        foreach ($param in $InstallerParameters) {
            $cleanParam = $param -replace '="([^"]*)"$', '=$1'
            if ($cleanParam -match '\s') {
                $argString += " `"$cleanParam`""
            }
            else {
                $argString += " $cleanParam"
            }
        }
    }

    Write-Verbose "Local params: $argString"
    $process = Start-InstallerProcess -FilePath $ExePath -ArgumentList $argString
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

    $Base = "EvoAgent"
    $suffix = "install"
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
        $LogFileName = Join-Path $Env:TEMP "EvoAgent_remove.log"
        $localParams += "/log"
        $localParams += $LogFileName
    }

    Write-Verbose "local params: $localParams"
    Start-InstallerProcess -FilePath "msiexec.exe" -ArgumentList $localParams | Out-Null
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
        $view.Execute() | Out-Null
        
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

function Get-ExeVersion {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ExePath
    )

    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath)
        $version = $versionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($version)) {
            $version = $versionInfo.FileVersion
        }
        if ([string]::IsNullOrWhiteSpace($version)) {
            return $null
        }

        return $version.Trim()
    }
    catch {
        Write-Error "Error reading EXE version: $_"
        return $null
    }
}

function GetServiceLocation {
	param (
		[string] $ServiceName
	)
	
	$Item = Get-ItemProperty "hklm:\System\CurrentControlSet\Services\$ServiceName" 'ImagePath' -ErrorAction Ignore
    if (-not $Item -or -not $Item.ImagePath) {
        return $null
    }

    return ($Item.ImagePath).Trim('"') # can be wrapped in quotes which we want to remove
}

function GetAgentLocation {
    $ServiceNames = @('EvoAgent', 'EvoSecureLoginAgent')

    foreach ($ServiceName in $ServiceNames) {
        $ServiceLocation = GetServiceLocation $ServiceName
        if ($ServiceLocation) {
            Write-Verbose "Found agent service location using service name: $ServiceName"
            return $ServiceLocation
        }
    }

    return $null
}

function SetCustomPrompt {
    param (
        [string]$CustomPrompt
    )

	Write-Verbose "CustomPrompt: $CustomPrompt"
	if (-not $CustomPrompt) { return }
	
	if (-not (IsRunningAsAdministrator)) {
		Write-Error "Must be running as an administrator to set a custom prompt"
		return
	}
	
	if (-not (Test-Path 'HKLM:\software\EvoSecurity\EvoLogin-CP')) {
		Write-Error "Registry key 'HKLM:\software\EvoSecurity\EvoLogin-CP' does not exist. Ensure the agent is properly installed."
		return
	}
	
	Set-ItemProperty 'HKLM:\software\EvoSecurity\EvoLogin-CP' 'login_text' $CustomPrompt
}

function SetCustomImage {
    param (
        [string] $CustomImage,
		[string] $AgentDirectory
    )
	
	Write-Verbose "CustomImage: $CustomImage, AgentDirectory: $AgentDirectory"
	if (-not $CustomImage -or -not $AgentDirectory) { return }
	
	if (-not (IsRunningAsAdministrator)) {
		Write-Error "Must be running as an administrator to set a custom image"
		return
	}
	
	if (Test-Path $CustomImage) {
	if (-not (Test-Path 'HKLM:\software\EvoSecurity\EvoLogin-CP')) {
		Write-Error "Registry key 'HKLM:\software\EvoSecurity\EvoLogin-CP' does not exist. Ensure the agent is properly installed."
		return
	}
	
	Set-ItemProperty 'HKLM:\software\EvoSecurity\EvoLogin-CP' 'v1_bitmap_path' $CustomImage
	} else {
		$GoodUri = [uri]::IsWellFormedUriString($CustomImage, 'Absolute') -and ([uri] $CustomImage).Scheme -in 'http', 'https'
		if (-not $GoodUri) {
			Write-Error "The supplied CustomImage parameter $CustomImage is neither a valid file path nor URL"
			return
		}
	
        try {
		    $WebContent = Invoke-WebRequest -uri $CustomImage -UseBasicParsing
		    $bytes = $WebContent.Content
        } catch {
			Write-Error "Unable to download image from $CustomImage"
			return
        }

        if (-not $bytes -or $bytes.length -lt 4) {
			Write-Error "Unable to download image from $CustomImage"
			return
        }
		
		$FileExt = $null
		if ($bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) {
            $FileExt = ".png"
        }
        elseif ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8) {
            $FileExt = ".jpg"
        }
        elseif ($bytes[0] -eq 0x42 -and $bytes[1] -eq 0x4D) {
            $FileExt = ".bmp"
        }
		
		if (-not $FileExt) {
			Write-Error "$CustomImage is not a valid image format (PNG, JPEG, or Bitmap)"
			return
		}
		
		$CustomImageFileName = Join-Path $AgentDirectory ("CustomImage" + $FileExt)
		Set-Content -value $bytes -path $CustomImageFileName -Encoding byte
		Set-ItemProperty 'hklm:\software\EvoSecurity\EvoLogin-CP' 'v1_bitmap_path' $CustomImageFileName
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
    Write-Verbose "Installing Evo Windows Agent..."
    # Write-Verbose "Parameters: EnvironmentUrl=$EnvironmentUrl; EvoDirectory=$EvoDirectory; Secret=$Secret; AccessToken=$AccessToken"
    $MapForJson = @{}

    $DeploymentToken = Get-DynamicToken -Token $DeploymentToken -RMM $RMM
    
    if ($DeploymentToken) {
        $MapForJson += @{ DeploymentToken = $DeploymentToken}
    }
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
    if ($CredentialMode) {
        $MapForJson += @{ CredentialMode = $CredentialMode}
    }
    if ($FailSafeUser) {
        $MapForJson += @{ FailSafeUser = $FailSafeUser}
    }
    if ($NoElevatedRDP) {
        $MapForJson += @{ NoElevatedRDP = $NoElevatedRDP}
    }
    if ($MFATimeOut -ne $null) {
        $MapForJson += @{ MFATimeOut = $MFATimeOut}
    }
    if ($null -ne $OnlyEvoLoginCredential) {
        $boolValue = $null
        if ($OnlyEvoLoginCredential -is [bool]) {
			$boolValue = $OnlyEvoLoginCredential
        } elseif ($OnlyEvoLoginCredential -in (1, "1", "True")) {
            $boolValue = $true
        } elseif ($OnlyEvoLoginCredential -in (0, "0", "False")) {
			$boolValue = $false
        }
        $MapForJson += @{ OnlyEvoLoginCredential = $boolValue }
    }
    if ($null -ne $DisableUpdate) {
        $MapForJson += @{ DisableUpdate = $DisableUpdate}
    }
    if ($null -ne $JitMode) {
        $MapForJson += @{ JitMode = $JitMode}
    }
    if ($null -ne $EndUserElevation) {
        $MapForJson += @{ EndUserElevation = $EndUserElevation}
    }
    if ($null -ne $UserAdminEscalation) {
        $MapForJson += @{ UserAdminEscalation = $UserAdminEscalation}
    }
    if ($null -ne $RememberLastUserName) {
        $MapForJson += @{ RememberLastUserName = $RememberLastUserName}
    }
    if ($null -ne $UACExtension) {
        $MapForJson += @{ UACExtension = $UACExtension}
    }
    if ($null -ne $DisableEvoLogin) {
        $MapForJson += @{ DisableEvoLogin = $DisableEvoLogin}
    }
    if ($null -ne $DisableEvoUac) {
        $MapForJson += @{ DisableEvoUac = $DisableEvoUac}
    }
    if ($null -ne $UnlimitedExtendedUacSession) {
        $MapForJson += @{ UnlimitedExtendedUacSession = $UnlimitedExtendedUacSession}
    }
    if ($null -ne $PersistentRequest) {
        $MapForJson += @{ PersistentRequest = $PersistentRequest}
    }
    if ($MSIPath) {
        $MapForJson += @{ MSIPath = $MSIPath}
    }
    if ($InstallerPath) {
        $MapForJson += @{ InstallerPath = $InstallerPath}
    }

    if ($MSIPath -and $InstallerPath) {
        throw "MSIPath and InstallerPath cannot both be supplied."
    }
	
	if ($CustomImage) {
		$MapForJson += @{ CustomImage = $CustomImage}
	}
	
	if ($CustomPrompt) {
		$MapForJson += @{ CustomPrompt = $CustomPrompt}
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

if ($ParamMap.MSIPath -and $ParamMap.InstallerPath) {
    throw "MSIPath and InstallerPath cannot both be supplied."
}

$InstallerParams = @(MakeMsiExecArgs $ParamMap)

$BaseUrl, $InfoUrl = GetBaseUrlAndInfoUrl -beta:$Beta

$ResolvedInstallerFile = $null
$TempInstallerFile = $null
$UseExeInstaller = $false

if (-not $ParamMap.MSIPath -and -not $ParamMap.InstallerPath) { ### we have to download the file ...

    $LatestInfo = GetLatestInfo $InfoUrl
    if ($Upgrade){
        VerifyVersionForUpgrade $LatestInfo.version
    }

    Write-Verbose "ParamMap MSIPath and InstallerPath are empty, downloading latest"
    $LatestUrl = $BaseUrl + $LatestInfo.Name
    Write-Verbose "Downloading latest URL: $LatestUrl"

    Write-Verbose "Checksum=$($LatestInfo.Checksum)"
    $TempInstallerFile = GetTempInstallerFrom-Uri $LatestUrl $LatestInfo.checksum # this creates a temp file which we will cleanup later
    $ResolvedInstallerFile = $TempInstallerFile
    $UseExeInstaller = $ResolvedInstallerFile.ToLower().EndsWith(".exe")
} elseif ($ParamMap.InstallerPath) {
    $resolved = Resolve-LocalInstallerPath -Path $ParamMap.InstallerPath -ParameterName "InstallerPath" -AllowExe
    $ResolvedInstallerFile = $resolved.ResolvedPath
    $TempInstallerFile = $resolved.TempFile
    $UseExeInstaller = $resolved.UseExeInstaller

    Test-LocalInstallerVersion -LocalInstallerPath $ResolvedInstallerFile -ParameterName "InstallerPath" -InstalledVersion $InstalledVersion -UseExeInstaller $UseExeInstaller
} else {
    $resolved = Resolve-LocalInstallerPath -Path $ParamMap.MSIPath -ParameterName "MSIPath"
    $ResolvedInstallerFile = $resolved.ResolvedPath
    $TempInstallerFile = $resolved.TempFile
    $UseExeInstaller = $resolved.UseExeInstaller

    Test-LocalInstallerVersion -LocalInstallerPath $ResolvedInstallerFile -ParameterName "MSIPath" -InstalledVersion $InstalledVersion -UseExeInstaller $UseExeInstaller
}

try {
    $DebugFlag = if ($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent) {$true} else {$false}
    Write-Output "Installer path: $ResolvedInstallerFile"
    Write-Output "InstallerParams: $(@($InstallerParams) | Where-Object {$DebugFlag -or (-not $_.StartsWith('APIKEY') -and -not $_.StartsWith('SECRET'))} )"

    if ($DebugFlag) {
        return "Quitting because Debug flag was used"
    }

    $LogFileName = if ($Log) { GetLogFileName $ProductType $true } else { "" }
    if ($UseExeInstaller) {
        InstallExe -ExePath $ResolvedInstallerFile -InstallerParameters $InstallerParams -Interactive $Interactive -LogFileName $LogFileName
    } else {
        InstallMsi -MsiPath $ResolvedInstallerFile -MsiParameters $InstallerParams -Interactive $Interactive -LogFileName $LogFileName
    }

    $JsonMap = ConvertFrom-Json (GetJsonRawContent $json)
    SetCustomPrompt $JsonMap.CustomPrompt

    if ($JsonMap.CustomImage) {
		$AgentLocation = GetAgentLocation
        Write-Verbose "AgentLocation: $AgentLocation"
        if ($AgentLocation -and (Test-Path $AgentLocation)) {
            $AgentDirectory = (Get-Item $AgentLocation).DirectoryName
            SetCustomImage $JsonMap.CustomImage $AgentDirectory
        } else {
            Write-Error "Could not find agent location; unable to apply CustomImage"
        }
    }
	
}
finally {
    if ($TempInstallerFile -and (Test-Path $TempInstallerFile)) {
        Write-Verbose "Deleting $TempInstallerFile"
        Remove-Item $TempInstallerFile
    }
}
