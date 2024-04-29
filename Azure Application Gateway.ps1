#
# Azure AppGateway - Manage Azure application gateways that have certificates
# loaded directly into their configuration (i.e. not using an Azure vault)
#

# Adaptable Application Template Version
#$Script:AdaptableTmpVer = '202309011535'

# Name and version of this adaptable application
$Script:AdaptableAppVer = '202404261652'
$Script:AdaptableAppDrv = 'Azure AppGateway'

# This driver requires the Az.Network module version 6.1.1 or equivalent
#Requires -Modules @{ ModuleName = 'Az.Network'; ModuleVersion = '6.1.1'}

<#

Adaptable Application Fields are defined one per line below in the following format:
 [Field Name] | [Field Label] | [Binary/Boolean Flags]
    flag #1: Enabled? (Will not be displayed if 0)
    Flag #2: Can be set at policy level?
    Flag #3: Mandatory?

You cannot add to, change, or remove the field names. Enable or disable as needed.

-----BEGIN FIELD DEFINITIONS-----
Text1|Azure Tenant ID|111
Text2|Text Field 2|000
Text3|Text Field 3|000
Text4|Azure Listener Name|101
Text5|Azure Resource ID|110
Option1|Debug This Driver|110
Option2|Yes/No #2|000
Passwd|Password Field|000
-----END FIELD DEFINITIONS-----

#>

# REMOTE KEY GENERATION SUPPORT (Stages 200, 300, 400) - NOT SUPPORTED BY THIS DRIVER

# Stage 800: OPTIONAL FUNCTION - NOT USED BY THIS DRIVER
# Provision each of the certificates in the CA trust chain
# This function supports the "ResumeLater" result code
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result = 'NotUsed' }
}

# Stage 801: OPTIONAL FUNCTION  - NOT USED BY THIS DRIVER
# Provision the private key associated with the certificate
# This function supports the "ResumeLater" result code
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result = 'NotUsed' }
}

# Stage 802: MANDATORY FUNCTION (unless Install-PrivateKey has been implemented)
# Provision the certificate. Can also provision the chain and private key.
# This function supports the "ResumeLater" result code
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    $General | Initialize-VenDebugLog
    $AzureProfile = $General | Connect-AzureApi

    # Retrieve configuration of the application gateway
    try {
        $AppGateway = Get-AppGateway $General $AzureProfile
    } catch {
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Check to see if certificate is already installed
    try {
        $CertificateCheck = @{
            ApplicationGateway = $AppGateway
            Name               = ($General.AssetName)
            DefaultProfile     = $AzureProfile
        }
        $ExistingCertificate = Get-AzApplicationGatewaySslCertificate @CertificateCheck
        if ($ExistingCertificate) {
            # certificate has already been uploaded to the application gateway
#            $CertificateCheck = $ExistingCertificate.PublicCertData | New-CertificateObject
#            Write-VenDebugLog "\\-- Subject $($CertificateCheck.X509.Subject)"
#            Write-VenDebugLog "\\-- Serial Number $($CertificateCheck.X509.SerialNumber)"
#            Write-VenDebugLog "\\-- Thumbprint $($CertificateCheck.X509.Thumbprint)"
            # TODO: Implement logic to validate correct cert is actually installed
            Write-VenDebugLog "Certificate $($ExistingCertificate.Name) Already Exists - Returning control to Venafi"
            return @{ Result = 'AlreadyInstalled' }
        }
    } catch {
        Write-VenDebugLog "Error while checking for certificate already being installed: $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Upload the certificate to the application gateway
    $TempPfxFile       = $Specific | Export-CertificateToDisk
    $UploadCertificate = @{
        ApplicationGateway = $AppGateway
        Name               = ($General.AssetName)
        CertificateFile    = ($TempPfxFile.FullName)
        Password           = (ConvertTo-SecureString $Specific.EncryptPass -AsPlainText -Force)
        DefaultProfile     = $AzureProfile
    }
    Write-VenDebugLog "Uploading certificate $($General.AssetName) to $($AppGateway.Name)"
    try {
#        $AppGateway = Add-AzApplicationGatewaySslCertificate @UploadCertificate
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Add-AzApplicationGatewaySslCertificate @using:UploadCertificate }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "Error while uploading certificate: $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Remove the temporary PFX certificate file
    Remove-Item $TempPfxFile.FullName -Force

    # Validate the certificate uploaded successfully
    $UploadValidation = @{
        ApplicationGateway = $AppGateway
        Name               = ($General.AssetName)
        DefaultProfile     = $AzureProfile
    }
    $ExistingCertificate = Get-AzApplicationGatewaySslCertificate @UploadValidation
    if ($ExistingCertificate) {
        Write-VenDebugLog "SSL certificate $($General.AssetName) has been uploaded successfully"
    } else {
        Write-VenDebugLog "Error validating upload of $($General.AssetName)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Save updated application gateway configuration (supports -AsJob)
    try {
        Write-VenDebugLog "Saving updated configuration for $($AppGateway.Name)"
#        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzureProfile
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Set-AzApplicationGateway -ApplicationGateway $using:AppGateway -DefaultProfile $using:AzureProfile }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "Configuration update failed on $([Environment]::MachineName). Set-AzApplicationGateway: $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }
    if (-not $AppGateway) {
        Write-VenDebugLog "Configuration update failed on $([Environment]::MachineName). (AppGateway is NULL)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    Write-VenDebugLog "Certificate Installed - Returning control to Venafi"
    return @{ Result = 'Success' }
}

# Stage 803: OPTIONAL FUNCTION
# Associate the provisioned certificate and private key to the application
# This function supports the "ResumeLater" result code
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result = 'NotUsed' }
}

# Stage 804: OPTIONAL FUNCTION
# Activate/Commit the updated certificate and private key for the application
# This function supports the "ResumeLater" result code
function Activate-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    $General | Initialize-VenDebugLog
    $AzureProfile = $General | Connect-AzureApi

    # Retrieve configuration of the application gateway
    try {
        $AppGateway = Get-AppGateway $General $AzureProfile
    } catch {
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Retrieve configuration of the HTTP listener
    $ListenerLookup = @{
        ApplicationGateway = $AppGateway
        Name               = ($General.VarText4.Trim())
        DefaultProfile     = $AzureProfile
    }
    try {
        $Listener = Get-AzApplicationGatewayHttpListener @ListenerLookup
        Write-VenDebugLog "Found Listener: $($Listener.Name)"
    } catch {
        Write-VenDebugLog "Listener lookup failed - $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Check to see if certificate is already installed
    try {
        $CertificateCheck = @{
            ApplicationGateway = $AppGateway
            Name               = ($General.AssetName)
            DefaultProfile     = $AzureProfile
        }
        $ExistingCertificate = Get-AzApplicationGatewaySslCertificate @CertificateCheck
    } catch {
        Write-VenDebugLog "Error while checking for certificate already being installed: $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }
    if ($ExistingCertificate) {
        Write-VenDebugLog "Found Certificate $($General.AssetName)"
    } else {
        Write-VenDebugLog "Error validating existence of $($General.AssetName)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Update the HTTP listener with the new certificate
    $ListenerUpdate = @{
        ApplicationGateway          = $AppGateway
        DefaultProfile              = $AzureProfile
        Name                        = ($Listener.Name)
        FrontendIPConfigurationId   = ($Listener.FrontendIpConfiguration.Id)
        FrontendPortId              = ($Listener.FrontendPort.Id)
        SslCertificateId            = ($ExistingCertificate.Id)
        RequireServerNameIndication = ($Listener.RequireServerNameIndication)
        Protocol                    = ($Listener.Protocol)
    }
    if ($Listener.FirewallPolicy) {
        $ListenerUpdate.FirewallPolicyId = $Listener.FirewallPolicy.Id
    }
    if ($Listener.HostName) {
        $ListenerUpdate.HostName = $Listener.HostName
    }
    #
    # CustomErrorConfigurations and/or HostNames can be non-null but have 0 entries.
    # This will be rejected by the Azure API so now we validate 1 or more entries exists.
    #
    # The argument is null, empty, or an element of the argument collection contains a null value.
    # Supply a collection that does not contain any null values and then try the command again.
    #
    if (($Listener.HostNames) -and ($Listener.HostNames.Count -ge 1)) {
        $ListenerUpdate.HostNames = $Listener.HostNames
    }
    if (($Listener.CustomErrorConfigurations) -and ($Listener.CustomErrorConfigurations.Count -ge 1)) {
        $ListenerUpdate.CustomErrorConfiguration = $Listener.CustomErrorConfigurations
    }

    $OldCertificate = ($Listener.SslCertificate.Id | ConvertTo-ResourceHash).sslCertificates
    Write-VenDebugLog "Replacing SSL Certificate: $($OldCertificate)"

    try {
#        $AppGateway = Set-AzApplicationGatewayHttpListener @ListenerUpdate
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Set-AzApplicationGatewayHttpListener @using:ListenerUpdate }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "Listener update failed - $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    # Save updated application gateway configuration (supports -AsJob)
    try {
#        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzureProfile
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Set-AzApplicationGateway -ApplicationGateway $using:AppGateway -DefaultProfile $using:AzureProfile }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "Application Gateway update failed - $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    Write-VenDebugLog "Certificate Activated - Returning control to Venafi"
    return @{ Result = 'Success' }
}

# VALIDATION: MANDATORY FUNCTION
# Extract public certificate information used for validation and possibly update the database
# Option 1: Extract and return the public certificate (and optionally the certificate chain)
# -- Option 1 can update the certificate in the TPP database
function Extract-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory, HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    $General | Initialize-VenDebugLog
    $AzureProfile = $General | Connect-AzureApi

    # Retrieve configuration of the application gateway
    $AppGateway = Get-AppGateway $General $AzureProfile

    # Retrieve configuration of the listener (VIP)
    $ListenerLookup = @{
        Name               = ($General.VarText4.Trim())
        ApplicationGateway = $AppGateway
        DefaultProfile     = $AzureProfile
    }
    try {
        $Listener = Get-AzApplicationGatewayHttpListener @ListenerLookup
    } catch {
        "Could not retrieve listener: $($_)" | Write-VenDebugLog -ThrowException
    }
    if ($Listener) {
        Write-VenDebugLog "Found Listener: $($Listener.Name)"
    } else {
        "Listener does not exist: $($ListenerLookup.Name)" | Write-VenDebugLog -ThrowException
    }

    # Retrieve certificate data
    $CertificateLookup = @{
        ID = $Listener.SslCertificate.Id
        ApplicationGateway = $AppGateway
    }
    $Certificate = Get-CertificateDetails @CertificateLookup

    Write-VenDebugLog "Task complete - Returning control to Venafi"
    return @{
        Result     = 'Success'
        CertPem    = $Certificate.PEM
        Serial     = $Certificate.X509.SerialNumber
        Thumbprint = $Certificate.X509.Thumbprint
    }
}

# VALIDATION: OPTIONAL FUNCTION - NOT USED BY THIS DRIVER
# Extract the certificate's private key
function Extract-PrivateKey
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result = 'NotUsed' }
}

# Stage 805: OPTIONAL FUNCTION
# Clean up past versions of the certificate if TPP has provisioned the certificate at least 3 times
function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    $General | Initialize-VenDebugLog
    $AzureProfile = $General | Connect-AzureApi

    # Retrieve configuration of the application gateway
    $AppGateway = Get-AppGateway $General $AzureProfile

    $RemoveCertificate = @{
        ApplicationGateway = $AppGateway
        Name               = ($Specific.AssetNameOld)
        DefaultProfile     = $AzureProfile
    }
    try {
#        $AppGateway = Remove-AzApplicationGatewaySslCertificate @RemoveCertificate
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Remove-AzApplicationGatewaySslCertificate @using:RemoveCertificate }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "Remove Certificate failed - $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    try {
#        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzureProfile
        # Run the Azure update as a lightweight thread that can be forcibly timed out
        $azJob = Start-ThreadJob -ScriptBlock { Set-AzApplicationGateway -ApplicationGateway $using:AppGateway -DefaultProfile $using:AzureProfile }

        # Wait up to 15 seconds for the thread to complete
        $azResult = $azJob | Wait-Job -Timeout 15

        # If the thread completed, receive the output
        if ($azResult.State -eq 'Completed') {
            $AppGateway = $azJob | Receive-Job
        }

        # Forcibly remove the job regardless of outcome
        $azJob | Remove-Job -Force

        # If cmdlet timed out or failed throw to the error block so we can retry later
        if (-not $azResult) {
            throw "Timeout exceeded"
        } elseif ($azResult.State -ne 'Completed') {
            throw "Job $($azResult.State)"
        }
    } catch {
        Write-VenDebugLog "AppGateway update after remove certificate failed - $($_)"
        Write-VenDebugLog "Invoking 'ResumeLater' to pause and retry later."
        return @{ Result = 'ResumeLater' }
    }

    Write-VenDebugLog "Removed Certificate '$($Specific.AssetNameOld)' - Returning control to Venafi"
    return @{ Result = 'Success' }
}

# DISCOVERY: OPTIONAL FUNCTION
# Required only for onboard discovery support
function Discover-Certificates
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory, HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    $started = Get-Date

    $General | Initialize-VenDebugLog
    $AzureProfile = $General | Connect-AzureApi

    # Retrieve configuration of the application gateway
    $AppGateway = Get-AppGateway $General $AzureProfile

    $ApplicationList = @()
    foreach ($listener in $AppGateway.HttpListeners) {
        if ($listener.Protocol -eq 'Https') {
            if ($listener.SslCertificate.Id -ne '') {
                Write-VenDebugLog "Discovered Listener $($listener.Name) [$($listener.SslCertificate.Id|Split-Path -Leaf)]"
                try {
                    $Certificate = Get-CertificateDetails -ID $listener.SslCertificate.Id -ApplicationGateway $AppGateway
                    # Add newly discovered application to results array
                    $ApplicationList += @{
                        Name              = ($listener.Name)   # Name of the Adaptable Application object
                        PEM               = ($Certificate.PEM) # Formatted PEM version of the public certificate
#                        ValidationAddress = ""                 # FQDN, hostname, or IP (httplistener->properties->frontendipconfiguration)
#                        ValidationPort    = 443                # TCP port (httplistener->properties->frontendport)
                        Attributes        = @{
                            'Text Field 1'     = ''
                            'Text Field 2'     = ''
                            'Text Field 3'     = ''
                            'Text Field 4'     = ($listener.Name)
                            'Text Field 5'     = ($listener.Id)
                            'Certificate Name' = ($listener.SslCertificate.Id|Split-Path -Leaf)
                        }
                    }
                } catch {
                    Write-VenDebugLog "Ignored Listener $($listener.Name) (no certificate)"
                }
            }
        } else {
            Write-VenDebugLog "Ignored Listener $($listener.Name) (unencrypted)"
        }
    }

    Write-VenDebugLog "Discovered $($ApplicationList.Count) Listeners on Application Gateway $($AppGateway.Name)"

    $runtime = New-TimeSpan -Start $started -End (Get-Date)
    Write-VenDebugLog "Scanned $($AppGateway.HttpListeners.Count) listeners (Runtime $($runtime)) - Returning control to Venafi"
    return @{ Result = "Success"; Applications = $ApplicationList }
}

# Private functions for this application driver

function Get-AppGateway
{
    Param(
        [Parameter(Position=0, Mandatory)]
        [System.Collections.Hashtable] $General,

        [Parameter(Position=1, Mandatory)] #[IAzureContextContainer]
        $DefaultProfile
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $AzureHash = $General.HostAddress | ConvertTo-ResourceHash

    $AppGatewaySearch = @{
        Name              = ($AzureHash.applicationGateways)
        ResourceGroupName = ($AzureHash.resourceGroups)
        DefaultProfile    = $DefaultProfile
    }

    # How many times do we retry the application gateway search..?
    $maxRetries = 3

    # retrieve application gateway
    try {
        $i=0
        do {
            $i++
            $AzError = $null
            $AppGateway = Get-AzApplicationGateway @AppGatewaySearch -ErrorVariable AzError
            if (-not $AppGateway) {
                if ($AzError) {
                    Write-VenDebugLog "Get-AzApplicationGateway failed:`n$($AzError|Out-String)"
                    Write-VenDebugLog "Azure Profile Context information:`n$($DefaultProfile.Context|Format-List|Out-String)"
                    Write-VenDebugLog "Available Contexts:`n$(Get-AzContext -DefaultProfile $DefaultProfile -ListAvailable|Out-String)"
                }
                if ($i -ge $maxRetries) {
                    "Could not retrieve Application Gateway (NULL after $($maxRetries) attempts)" | Write-VenDebugLog -ThrowException
                } else {
                    $wait = Get-Random -Minimum ($i*2) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on $($AzureHash.applicationGateways) Sub: $($AzureHash.subscriptions) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while (-not $AppGateway)
        Write-VenDebugLog "Found Application Gateway: $($AppGateway.Name)"
    } catch {
        "Get-AzApplicationGateway has failed - $($_)" | Write-VenDebugLog -ThrowException
    }

    $AppGateway
}

function Get-CertificateDetails
{
    Param(
        [Parameter(Mandatory)]
        [Alias('CertificateID')]
        [string] $ID,

        [Parameter(Mandatory)]
        $ApplicationGateway
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $ByteString = (($ApplicationGateway.SslCertificates | Where-Object -Property Id -EQ $ID).PublicCertData)

    if (-not $ByteString) {
        "Certificate ID not found: $($ID)" | Write-VenDebugLog -ThrowException
    }

    $ByteString | New-CertificateObject
}

function New-CertificateObject
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [string] $ByteString
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    Add-Type -AssemblyName System.Security
    $CertBundle = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $CertBundle.Decode([Convert]::FromBase64String($ByteString))

    if ($CertBundle.Certificates.Count -eq 0) {
        Write-VenDebugLog "No certificates found in bundle!!"
        return
    } elseif ($CertBundle.Certificates.Count -eq 1) {
        Write-VenDebugLog "No chain - Bundle contains only 1 certificate"
        $missed = 0
        $Current = $Last = $CertBundle.Certificates[0]
        $FormattedPem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($Current.RawData,'InsertLineBreaks'))`n-----END CERTIFICATE-----`n"
#        $FormattedPem = "subject=$($Current.Subject)`n$($FormattedPem)"
        Write-VenDebugLog "Subject: $($Current.Subject)"
    } else {
        Write-VenDebugLog "Bundle contains $($CertBundle.Certificates.Count) certificates"
        $Root = $CertBundle.Certificates | Where-Object -FilterScript { $_.GetNameInfo(0,$false) -eq $_.GetNameInfo(0,$true) }
        $Last = $Current = $Root
        $missed = $CertBundle.Certificates.Count
        $FormattedPem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($Current.RawData,'InsertLineBreaks'))`n-----END CERTIFICATE-----`n"
#        $FormattedPem = "subject=$($Current.Subject)`n$($FormattedPem)"
        Write-VenDebugLog "Root/Anchor: $($Current.Subject)"
        do {
            $missed--
            $Current = $CertBundle.Certificates | Where-Object -FilterScript { $_.GetNameInfo(0,$true) -eq $Current.GetNameInfo(0,$false) -and $_.GetNameInfo(0,$true) -ne $_.GetNameInfo(0,$false) }
            if ($Current) {
                $Last = $Current
                $FormattedPem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($Current.RawData,'InsertLineBreaks'))`n-----END CERTIFICATE-----`n$($FormattedPem)"
#                $FormattedPem = "subject=$($Current.Subject)`n$($FormattedPem)"
                Write-VenDebugLog "Next in chain: $($Current.Subject)"
            }
        } while ($Current)
    
        if ($missed) {
            Write-VenDebugLog "Warning: $($missed) certificates in bundle were not linked..!"
        }
    }
    
    if (($CertBundle.Certificates.Count - $missed) -gt 1) { $chain = 'chain ' }
    Write-VenDebugLog "Returning certificate $($chain)for $($Last.GetNameInfo(0,$false))"

    $CertResults = @{
        X509 = $Last
        PEM  = $FormattedPem
    }

    $CertResults
}

function Export-CertificateToDisk
{
    Param(
        [Parameter(Mandatory, ValueFromPipeline, HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    try {
        $TempPfxFile = New-TemporaryFile
    } catch {
        throw "TempFile creation failed on $([Environment]::MachineName): ($($_))"
    }

    Write-VenDebugLog "PFX temporary filename: [$($TempPfxFile.FullName)]"

    try {
        [IO.File]::WriteAllBytes($TempPfxFile.FullName, $Specific.Pkcs12)
    } catch {
        "Certificate export failed on $([Environment]::MachineName): ($($_))" | Write-VenDebugLog -ThrowException
    }

    $TempPfxFile
}

# Connect to the Azure API using specific named contexts
# Return IAzureContextContainer object if successful
function Connect-AzureApi
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [System.Collections.Hashtable] $General
    )

    $FunctionCall = (Get-PSCallStack)[1].Command
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $AzureHash     = ConvertTo-ResourceHash -AzureResourceId $General.HostAddress.Trim()
    $Subscription  = $AzureHash.subscriptions
    $ResourceGroup = $AzureHash.resourceGroups
    $AppGwName     = $AzureHash.applicationGateways
    $ListenerName  = $General.VarText4.Trim()
    $TenantID      = $General.VarText1

    # How many times do we try to connect to Azure or set the context..?
    $maxRetries = 3

    # Create Azure Context name
    $AzContext = "$([Environment]::MachineName).$($FunctionCall).$($TenantID).$($Subscription).$($ResourceGroup).$($AppGwName)"
    if ($ListenerName) { $AzContext += ".$($ListenerName)" }

    # Create Azure credential object
    $SecurePW   = ConvertTo-SecureString -AsPlainText ($General.UserPass) -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($General.UserName),$SecurePW

    $AzureConnectionParameters = @{
        Credential       = $Credential
        ContextName      = $AzContext
        Subscription     = $Subscription
        Tenant           = $TenantID
        Scope            = 'Process'
        Force            = $true
        ServicePrincipal = $true
        SkipContextPopulation = $true
    }

    Enable-AzContextAutosave | Out-Null

    # Connect to the Azure API using the provided service principal
    $i=0
    Write-VenDebugLog "Azure Tenant '$($TenantID)', Subscription '$($Subscription)'"
    Write-VenDebugLog "Connecting to Azure API as Service Principal $($General.UserName)"
    do {
        $i++
        if ($i -gt 1) {
            $s = 's'
            $wait = Get-Random -Minimum ($i*2) -Maximum ($i*3)
            Write-VenDebugLog "...Sleeping for $($wait) seconds before retrying"
            Start-Sleep -Seconds $wait
        } else {
            $s = ''
        }
        try {
            $AzProfile = Connect-AzAccount @AzureConnectionParameters
        } catch {
            Write-VenDebugLog "Connect-AzAccount has failed $($i) time$($s): $($_)"
            if ($i -gt $maxRetries) {
                Write-VenDebugLog '...Aborting'
                throw $_
            }
        }
    } while (-not $AzProfile)

    $DeviceDetails = "Resource Group '$($ResourceGroup)', Application Gateway '$($AppGwName)'"
    if ($ListenerName) {
        $DeviceDetails += ", Listener '$($ListenerName)'"
    }
    Write-VenDebugLog $DeviceDetails

    $AzureContextParameters = @{
        Name           = $AzContext
        Subscription   = $Subscription
        Scope          = 'Process'
        Force          = $true
        DefaultProfile = $AzProfile
    }

    # Create the Azure context for this run of the driver
    Write-VenDebugLog "Creating Context: $($AzContext)"
    $i=0
    do {
        $i++
        if ($i -gt 1) {
            $s = 's'
            $wait = Get-Random -Minimum ($i*2) -Maximum ($i*3)
            Write-VenDebugLog "...Sleeping for $($wait) seconds before retrying"
            Start-Sleep -Seconds $wait
        } else {
            $s = ''
        }
        try {
            $AzContext = Set-AzContext @AzureContextParameters
        } catch {
            Write-VenDebugLog "Set-AzContext has failed $($i) time$($s): $($_)"
            if ($i -gt $maxRetries) {
                Write-VenDebugLog '...Aborting'
                throw $_
            }
        }
    } while (-not $AzContext)

    $AzContext
}

# Utility functions - somewhat generic

function ConvertTo-ResourceHash
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [Alias('AzureResourceString')]
        [string] $AzureResourceId
    )

    Process {
        $Pieces    = $AzureResourceId.Trim('/').Split('/')
        $Hashtable = @{}
        $i         = 0
        do {
            $Hashtable.Add($Pieces[$i], $Pieces[$i+1])
            $i += 2
        } while ($i -lt $Pieces.Count)

        $Hashtable
    }
}

# Logging functions - Initialize-VenDebugLog and Write-VenDebugLog

# Take a message, prepend a timestamp, output it to a debug log ... if DEBUG_FILE is set
# Otherwise do nothing and return nothing
function Write-VenDebugLog
{
    Param(
        [Parameter(Position=0, ValueFromPipeline, Mandatory)]
        [string] $LogMessage,

        [Parameter()]
        [switch] $ThrowException,

        [Parameter()]
        [switch] $NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # if the logfile isn't initialized then do nothing and return immediately
    if ($null -eq $Script:venDebugFile) { return }

    if ($NoFunctionTag.IsPresent) {
        $taggedLog = $LogMessage
    } else {
        $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
    }

    # write the message to the debug file
    Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile

    # throw the message as an exception, if requested
    if ($ThrowException.IsPresent) {
        throw $LogMessage
    }
}

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [System.Collections.Hashtable] $General
    )

    if ($Script:venDebugFile) {
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog called more than once!'
        return
    }

    # Support policy-level debug flag instead of forcing every app to be flagged
    if ($DEBUG_FILE) {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = $DEBUG_FILE | Split-Path
    } else {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }

        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }

    $HostAddress = (($General.HostAddress.Trim()|ConvertTo-ResourceHash).applicationGateways)

    $Script:venDebugFile = ("$($logPath)\$($Script:AdaptableAppDrv.Replace(' ','')) $($HostAddress)").TrimEnd() + '.log'
    Write-Output '' | Add-Content -Path $Script:venDebugFile

    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
}

# END OF SCRIPT