#
# Azure AppGW - An Adaptable Application Driver for Venafi
#
# Template Driver Version: 202006081054
$Script:AdaptableAppVer = "202202021917"
$Script:AdaptableAppDrv = "Azure AppGW"

<#

Adaptable Application Fields are defined one per line below in the following format:
 [Field Name] | [Field Label] | [Binary/Boolean Flags]
    flag #1: Enabled? (Will not be displayed if 0)
    Flag #2: Can be set at policy level?
    Flag #3: Mandatory?

You cannot add to, change, or remove the field names. Enable or disable as needed.

-----BEGIN FIELD DEFINITIONS-----
Text1|Text Field 1|000
Text2|Text Field 2|000
Text3|Text Field 3|000
Text4|Azure Listener Name|101
Text5|Azure Resource ID|110
Option1|Debug Azure Application Gateway Driver|110
Option2|Yes/No #2|000
Passwd|Password Field|000
-----END FIELD DEFINITIONS-----

#####
##### In order to deal with limitations of the platform, we can
##### change the login ID synthetically to actually be:
#####
##### AppID@TenantID
#####
##### AppID is the ID assigned to the service principal
##### TenantID is the tenant ID required for the SP to login...
#####

#####
##### A device must be created that maps to an Azure Application Gateway
#####
##### The name of the host is unimportant, but the Hostname/Address field must be
##### set to the Azure Resource ID for the Application Gateway. This is crucial!
#####
##### /subscriptions/123a-7cd8-90e1-234f-5678gh/resourceGroups/MyNetworkRG/providers/Microsoft.Network/applicationGateways/MyAGW
#####
##### The resource ID in the Hostname/Address field is parsed for all relevant
##### info required by this application driver.
#####

##### Listener Name - REQUIRED: Maps application to Azure Listener, i.e. 'MyAGW'
##### Azure Resource ID - Populated by discovery as a courtesy reference

Thoughts on limitations...
* restrict to OperationalState=Running and ProvisioningState=Succeeded ..?

#>

#
# The following 3 functions are required only for remote key generation support.
# If commented out, the driver will assume this feature is not supported.
#

<#
# REMOTE KEY GENERATION SUPPORT - COMMENTED OUT = DISABLED

function Prepare-KeyStore
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

function Generate-KeyPair
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

function Generate-CSR
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="Success"; Pkcs10="-----BEGIN CERTIFICATE REQUEST-----..."; }
}

# REMOTE KEY GENERATION SUPPORT - COMMENTED OUT = DISABLED
#>

#
# REQUIRED FUNCTIONS
#
# Extract-Certificate >>> must always be implemented. it is required for validation.
#
# Install-Certificate >>> generally required to be implemented. You can optionally
# return "NotUsed" for this function *ONLY* if you instead implement Install-PrivateKey
# for your driver. In most cases, you will need Install-Certificate only. The function
# Install-Chain is also available if you need to implement certificate installation
# using 3 different functions for the public, private, and chain certificates.
#

function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

# MANDATORY FUNCTION
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $AzUser[1]
    $LocalHost = [Environment]::MachineName
    
    Initialize-VenDebugLog -AppGW $AppGwName -Listener $ListenerName

    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"
    Write-VenDebugLog "Service Principal:   [$($AzSpName)]"
    Write-VenDebugLog "Global Debug File:   [$($DEBUG_FILE)]"

#    Write-Output "`nGeneral Hashtable`n" >> $Script:V2Afile
#    Write-Output $General >> $Script:V2Afile
#    Write-Output "`nSpecific Hashtable`n" >> $Script:V2Afile
#    Write-Output $Specific >> $Script:V2Afile

    try {
        $TempPfxFile = New-TemporaryFile
    } catch {
        throw "$($LocalHost): TempFile creation failed: ($($_))"
    }

    Write-VenDebugLog "PFX filename:        [$($TempPfxFile.FullName)]"
    Write-VenDebugLog "PFX password:        [$($Specific.EncryptPass)]"

# X509KeyStorageFlags - bitfield
#
#  0: The default key set is used. The user key set is usually the default.
#  1: Private keys are stored in the current user store rather than the local computer store.
#  2: Private keys are stored in the local computer store rather than the current user store.
#  4: Imported keys are marked as exportable.
#  8: User Protected - Notify the user through a dialog box or other method that the key is accessed.
# 16: The key associated with a PFX file is persisted when importing a certificate.
# 32: Ephemeral - The key is created in memory and not persisted on disk when importing a certificate.

    $X509StorageFlags = 32

    $CertGroup = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    try {
        $CertGroup.Import($Specific.Pkcs12,$Specific.EncryptPass,$X509StorageFlags)
        $i=0
        foreach ($Cert in $CertGroup) {
            $i++
            Write-VenDebugLog "Chain Entity #$($i)"
            Write-VenDebugLog "\\-- Subject $($Cert.Subject)"
            Write-VenDebugLog "\\-- Serial Number $($Cert.SerialNumber)"
            Write-VenDebugLog "\\-- Thumbprint $($Cert.Thumbprint)"
            $NewCert = $Cert
        }
    } catch {
        throw "$($LocalHost): Invalid certificate: ($($_))"
    }

    try {
        [IO.File]::WriteAllBytes($TempPfxFile.FullName,$Specific.Pkcs12)
    } catch {
        throw "$($LocalHost): Certificate export failed: ($($_))"
    }

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($AzContext -eq $null) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on AzContext Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($AzContext -eq $null)
    } catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
#Write-Output $AppGateway.SslCertificates >> $Script:V2Afile
    } catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    try {
        # check to see if certificate is already defined
        $AzSslCert = Get-AzApplicationGatewaySslCertificate -Name $General.AssetName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        if ($AzSslCert -eq $null) {
            # doesn't exist - need to upload the certificate
            Write-VenDebugLog "SSL Certificate entry $($General.AssetName) not found - attempting upload"
            $PfxPW = ConvertTo-SecureString $Specific.EncryptPass -AsPlainText -Force
            $AppGateway = Add-AzApplicationGatewaySslCertificate -ApplicationGateway $AppGateway -Name $General.AssetName -CertificateFile $TempPfxFile.FullName -Password $PfxPW -DefaultProfile $AzContext
            $AzSslCert = Get-AzApplicationGatewaySslCertificate -Name $General.AssetName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
            if ($AzSslCert -eq $null) {
                throw "Can't find uploaded cert"
            }
        } else {
            # certificate has already been uploaded to the application gateway
            Write-VenDebugLog "SSL certificate $($AzSslCert.Name) is already installed"
            Convert-Bytes2X509 $AzSslCert.PublicCertData
            $ExistingCert = Convert-Bytes2X509 -ByteString $AzSslCert.PublicCertData
            Write-VenDebugLog "\\-- Subject $($ExistingCert.X509.Subject)"
            Write-VenDebugLog "\\-- Serial Number $($ExistingCert.X509.SerialNumber)"
            Write-VenDebugLog "\\-- Thumbprint $($ExistingCert.X509.Thumbprint)"
            Write-VenDebugLog "Certificate Already Exists - Returning control to Venafi TPP"
            return @{ Result="AlreadyInstalled"; }
        }
    } catch {
        throw "Error looking for existing cert - $($_)"
    }

    # save new certificate to application gateway configuration
    try {
        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzContext #-Verbose *>> $Script:V2Afile
        if ($AppGateway -eq $null) {
            throw "Updated AGW is NULL"
        }
    } catch {
        throw "$($LocalHost): Set-AzApplicationGateway failed - $($_)"
    }

    Remove-Item $TempPfxFile.FullName -Force

    Write-VenDebugLog "Certificate Installed - Returning control to Venafi TPP"

    return @{ Result="Success"; }
}

function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

function Activate-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $AzUser[1]
    $LocalHost = [Environment]::MachineName

    $CertName = $General.AssetName
    
    Initialize-VenDebugLog -AppGW $AppGwName -Listener $ListenerName

#    Write-Output "`nGeneral Hashtable`n" >> $Script:V2Afile
#    Write-Output $General >> $Script:V2Afile

    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"
    Write-VenDebugLog "Certificate Name:    [$($CertName)]"
    Write-VenDebugLog "Service Principal:   [$($AzSpName)]"
    Write-VenDebugLog "Global Debug File:   [$($DEBUG_FILE)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($AzContext -eq $null) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on AzContext Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($AzContext -eq $null)
    } catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
#Write-Output $AppGateway.SslCertificates >> $Script:V2Afile
    } catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    # retrieve http listener
    try {
        $Listener = Get-AzApplicationGatewayHttpListener -Name $ListenerName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found Listener: $($ListenerName)"
        Write-VenDebugLog "\\-- $($Listener.Id)"
#Write-Output $Listener >> $Script:V2Afile
    } catch {
        Write-VenDebugLog "Get-AzApplicationGatewayHttpListener has failed - $($_)"
        throw "$($LocalHost): Get-AzApplicationGatewayHttpListener has failed - $($_)"
    }

    # retrieve installed certificate information
    try {
        $AzCertificate = Get-AzApplicationGatewaySslCertificate -Name $CertName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found SSL Certificate: $($CertName)"
        Write-VenDebugLog "\\-- $($AzCertificate.Id)"
#Write-Output $AzCertificate >> $Script:V2Afile
    } catch {
        Write-VenDebugLog "Get-AzApplicationGatewaySslCertificate has failed - $($_)"
        throw "$($LocalHost): Get-AzApplicationGatewaySslCertificate has failed - $($_)"
    }

    $OldSslCert = Convert-AzResource2Hash -AzResourceId $Listener.SslCertificate.Id
    Write-VenDebugLog "Replacing SSL Certificate: $($OldSslCert['sslCertificates'])"
    Write-VenDebugLog "\\-- $($Listener.SslCertificate.Id)"

    try {
        $ListenerHash = @{
            Name = $ListenerName
            FrontendIPConfigurationId = $Listener.FrontendIpConfiguration.Id
            FrontendPortId = $Listener.FrontendPort.Id
            SslCertificateId = $AzCertificate.Id
            RequireServerNameIndication = $Listener.RequireServerNameIndication
            Protocol = $Listener.Protocol
        }
        if ($Listener.FirewallPolicy -ne $null) {
            $ListenerHash.Add('FirewallPolicyId',$Listener.FirewallPolicy.Id)
        }
        if ($Listener.HostName -ne $null) {
            $ListenerHash.Add('HostName',$Listener.HostName)
        }
        if ($Listener.HostNames -ne $null) {
            $ListenerHash.Add('HostNames',$Listener.HostNames)
        }
        if ($Listener.CustomErrorConfigurations -ne $null) {
            $ListenerHash.Add('CustomErrorConfiguration',$Listener.CustomErrorConfigurations)
        }
        $AppGateway = Set-AzApplicationGatewayHttpListener -ApplicationGateway $AppGateway @ListenerHash -DefaultProfile $AzContext
#Write-Output $AppGateway.HttpListeners >> $Script:V2Afile
    } catch {
        Write-VenDebugLog "Set-AzApplicationGatewayHttpListener has failed - $($_)"
        throw "$($LocalHost): Set-AzApplicationGatewayHttpListener has failed - $($_)"
    }

    try {
        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzContext
    } catch {
        Write-VenDebugLog "Set-AzApplicationGateway has failed - $($_)"
        throw "$($LocalHost): Set-AzApplicationGateway has failed - $($_)"
    }

    Write-VenDebugLog "Certificate Activated - Returning control to Venafi TPP"
    return @{ Result="Success"; }
}

# MANDATORY FUNCTION
function Extract-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $AzUser[1]
    
    Initialize-VenDebugLog -AppGW $AppGwName -Listener $ListenerName

    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"
    Write-VenDebugLog "Service Principal:   [$($AzSpName)]"
    Write-VenDebugLog "Global Debug File:   [$($DEBUG_FILE)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($AzContext -eq $null) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on AzContext Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($AzContext -eq $null)
    } catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    } catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    # retrieve https listener
    try {
        $Listener = Get-AzApplicationGatewayHttpListener -Name $ListenerName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found Listener: $($Listener.Name)"
        Write-VenDebugLog "\\-- $($Listener.Id)"
    } catch {
        Write-VenDebugLog "Get-AzApplicationGatewayHttpListener call failed - $($_)"
        throw $_
    }

    # retrieve certificate data
    Write-VenDebugLog 'Searching for SSL Certificate...'
    Write-VenDebugLog "\\-- $($Listener.SslCertificate.Id)"
    try {
        $Cert = Get-Ven2AzCertById -CertificateId $Listener.SslCertificate.Id -ApplicationGateway $AppGateway
    } catch {
        Write-VenDebugLog "SSL certificate not found for Listener $($ListenerName)"
        throw "SSL certificate not found for Listener $($ListenerName)"
    }
    Write-VenDebugLog "Certificate Subject:       $($Cert.X509.Subject)"
    Write-VenDebugLog "Certificate Serial Number: $($Cert.X509.SerialNumber)"
    Write-VenDebugLog "Certificate Thumbprint:    $($Cert.X509.Thumbprint)"

    Write-VenDebugLog "Disconnecting from Azure API"
    Disconnect-Ven2AzGateway

    Write-VenDebugLog "Certificate Extracted - Returning control to Venafi TPP"
    return @{ Result="Success"; CertPem=$Cert.PEM; Serial=$Cert.X509.SerialNumber; Thumbprint=$Cert.X509.Thumbprint }
}

#
# Onboard Discovery support for Azure Application Gateways - This works only for directly uploaded certificates
# >>> Azure key vault support has not been baked in (yet)
#
# This relies on the Application Gateway "Hostname/Address" field being set to the Azure resource ID:
# /subscriptions/<SubscriptionID>/resourceGroups/<Network RG>/providers/Microsoft.Network/applicationGateways/<AppGW-Name>
#
function Discover-Certificates
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    $AzSpPass = $General.UserPass

    if ($General.HostAddress.Trim() -notlike '/?*/?*') {
        return @{ Result = "NotUsed"; }
    }
    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $AzUser[1]

    Initialize-VenDebugLog -AppGW $AppGwName

    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Service Principal:   [$($AzSpName)]"
    Write-VenDebugLog "Global Debug File:   [$($DEBUG_FILE)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($AzContext -eq $null) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on AzContext Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($AzContext -eq $null)
    } catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    } catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    $ApplicationList = @()
    foreach ($aListener in $AppGateway.HttpListeners) {
        if ($aListener.Protocol -eq 'Https') {
            if ($aListener.SslCertificate.Id -ne '') {
                Write-VenDebugLog "Found Https Listener [$($aListener.Name)]"
                Write-VenDebugLog "\\-- Cert [$($aListener.SslCertificate.Id)]"
                try {
                    $Cert = Get-Ven2AzCertById -CertificateId $aListener.SslCertificate.Id -ApplicationGateway $AppGateway
                    Write-VenDebugLog "\\-- Subject $($Cert.X509.Subject)"
                    Write-VenDebugLog "\\-- Serial Number $($Cert.X509.SerialNumber)"
                    Write-VenDebugLog "\\-- Thumbprint $($Cert.X509.Thumbprint)"
                    # add valid listener+cert to return stack
                    $anApp = @{
                        Name = "$($aListener.Name)" # Name of the Adaptable Application object
                        PEM = "$($Cert.PEM)"        # Formatted PEM version of the public certificate
#                        ValidationAddress = ""      # FQDN, hostname, or IP (httplistener->properties->frontendipconfiguration)
#                        ValidationPort = 443        # TCP port (httplistener->properties->frontendport)
                        Attributes = @{
                            "Text Field 1" = ""
                            "Text Field 2" = ""
                            "Text Field 3" = ""
                            "Text Field 4" = "$($aListener.Name)"
                            "Text Field 5" = "$($aListener.Id)"
                            "Certificate Name" = "$($aCert.Name)"
                        }
                    }
                    $ApplicationList += $anApp
                } catch {
                    Write-VenDebugLog "Listener [$($aListener.Name)] has no certificate - ignored"
                }
            }
        } else {
            Write-VenDebugLog "Listener [$($aListener.Name)] is unencrypted - ignored"
        }
    }

    Write-VenDebugLog "Disconnecting from Azure API"
    Disconnect-Ven2AzGateway

    Write-VenDebugLog "Discovered $($ApplicationList.Count) Listeners on Application Gateway $($AppGateway.Name)"

    return @{ Result = "Success"; Applications = $ApplicationList }
}

function Extract-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

#
# Internal Support Functions for Adaptable Application
#

function Connect-Ven2Azure
{
    Param(
        [Parameter(Mandatory=$true)][string]$AppId,
        [Parameter(Mandatory=$true)][string]$AppPw,
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$SubscriptionId
    )

    Write-VenDebugLog "Disabling Azure context autosaving..."
    Clear-AzContext -Scope Process | Out-Null
    Disable-AzContextAutosave -Scope Process | Out-Null

    # convert username+password to credential $AzCredential
    $securePw = ConvertTo-SecureString -AsPlainText $AppPw -Force
    $AzCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppId,$securePw
    Write-VenDebugLog "Connecting to Azure API as Service Principal $($AzCredential.UserName)"

    # connect to the Azure account
    try {
        $SpProfile = Connect-AzAccount -Credential $AzCredential -Subscription $SubscriptionId -TenantId $TenantId -ServicePrincipal -SkipContextPopulation
    } catch {
        Write-VenDebugLog "Connect-AzAccount has failed - $($_)"
        throw $_
    }

    $SpProfile
}

function Disconnect-Ven2AzGateway
{
    Disconnect-AzAccount
}

Function Convert-Bytes2X509
{
    Param( [Parameter(Mandatory=$true,Position=0)][string]$ByteString )

    $CertBytes = [Convert]::FromBase64String($ByteString)
    Add-Type -AssemblyName System.Security
    $P7B = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $P7B.Decode($CertBytes)

    Write-VenDebugLog "START: Convert-Bytes2X509"
    Write-VenDebugLog "\\-- Certificate bundle contains $($P7B.Certificates.Count) certificates"
    
    $CertOrder = @()
    if ($P7B.Certificates.Count -eq 1) {
        # Only 1 certificate so use that one
        $ServerAt=0
        $CertOrder += $ServerAt
    } else {
        # find the self-signed root certificate first
        $i=0
        foreach ($aCert in $P7B.Certificates) {
            $CertCN = $aCert.GetNameInfo(0,$false)
            $Issuer = $aCert.GetNameInfo(0,$true)
            if ($CertCN -eq $Issuer) {
                Write-VenDebugLog "\\-- Selecting certificate #$($i+1) of $($P7B.Certificates.Count) as ROOT"
#                Write-VenDebugLog "\\-- ROOT: Subject:       $($aCert.Subject)"
                Write-VenDebugLog "\\-- ROOT: Common Name:   $($CertCN)"
                Write-VenDebugLog "\\-- ROOT: Serial Number: $($aCert.SerialNumber)"
                Write-VenDebugLog "\\-- ROOT: Thumbprint:    $($aCert.Thumbprint)"
                $RootAt = $i
                $CertOrder += $RootAt
                break
            }
            $i++
        }

        $CurrentCert=$RootAt
        do {
            $i=0
            $CurrentCN=$P7B.Certificates[$CurrentCert].GetNameInfo(0,$false)
            foreach ($aCert in $P7B.Certificates) {
                $Issuer = $aCert.GetNameInfo(0,$true)
                if (($Issuer -eq $CurrentCN) -and ($CurrentCert -ne $i)) {
                    # this cert was issued by our last processed cert in the chain!
                    $CertOrder += $i
                    $CurrentCert=$i
                    if ($CertOrder.Count -lt $P7B.Certificates.Count) {
                        # this is a chain cert
                        $CertType='CHAIN'
                    } else {
                        # this is the server cert
                        $ServerAt=$i
                        $CertType='SERVER'
                    }
                    $CertCN = $aCert.GetNameInfo(0,$false)
                    $Issuer = $aCert.GetNameInfo(0,$true)
                    Write-VenDebugLog "\\-- Selecting certificate #$($i+1) of $($P7B.Certificates.Count) as $($CertType)"
#                    Write-VenDebugLog "\\-- $($CertType): Subject:       $($aCert.Subject)"
                    Write-VenDebugLog "\\-- $($CertType): Common Name:   $($CertCN)"
                    Write-VenDebugLog "\\-- $($CertType): Issuer:        $($Issuer)"
                    Write-VenDebugLog "\\-- $($CertType): Serial Number: $($aCert.SerialNumber)"
                    Write-VenDebugLog "\\-- $($CertType): Thumbprint:    $($aCert.Thumbprint)"
                    break    # end this foreach iteration
                }
                $i++
                if ($i -ge $P7B.Certificates.Count) {
                    # that's bad... certificate we couldn't place in the chain. time to die.
                    throw "Convert-Bytes2X509: Could not sort certificate chain"
                }
            }
        } while ($CertOrder.Count -lt $P7B.Certificates.Count)
    }

    # build and attach the root certificate information
    if ($CertOrder.Count -gt 1) {
        $CertOrderString = ''
        foreach ($CertNum in $CertOrder) {
            if ($CertOrderString.Length -gt 0) {
                $CertOrderString += "-->"
            }
            $CertOrderString += "$($CertNum+1)"
        }
        Write-VenDebugLog "Final Certificate Order (Root-->Chain-->Server): $($CertOrderString)"
        $RootCert = $P7B.Certificates[$RootAt]
        $RawPEM = [Convert]::ToBase64String($RootCert.RawData,'InsertLineBreaks')
        $FormattedPem = "-----BEGIN CERTIFICATE-----`n$($RawPEM)`n-----END CERTIFICATE-----"
        $RootResults = @{
            X509   = $RootCert
            PEM    = $FormattedPem
            RawPEM = $RawPEM
        }
    } else {
        $RootResults = $null
    }

    Write-VenDebugLog "END: Convert-Bytes2X509 (Returning certificate #$($ServerAt+1))"
    $ServerCert = $P7B.Certificates[$ServerAt]
    $RawPEM = [Convert]::ToBase64String($ServerCert.RawData,'InsertLineBreaks')
    $FormattedPem = "-----BEGIN CERTIFICATE-----`n$($RawPEM)`n-----END CERTIFICATE-----"

    $CertResults = @{
        X509   = $ServerCert
        PEM    = $FormattedPem
        RawPEM = $RawPEM
        Root   = $RootResults
    }

    $CertResults
}

#function Convert-PEM2X509
#{
#    Param(
#        [Parameter(Mandatory=$true)][string]$PemString,
#        [switch]$Azure
#    )
#
#    $PemString = $PemString.Trim()
#    if ($Azure -eq $true) {
#        $PemString = $PemString.Substring(60,$PemString.Length-60)
#    }
#    if (!$PemString.StartsWith('M') -and !$PemString.EndsWith('=')) {
#        throw 'ABORT: Invalid PEM format!'
#    }
#
#    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
#    try {
#        $Cert.Import([Convert]::FromBase64String($PemString))
#    } catch {
#        throw "Invalid certificate: ($($_))"
#    }
#
#    $FormattedPem = "-----BEGIN CERTIFICATE-----`n$($PemString)`n-----END CERTIFICATE-----"
#
#    $PemResult = @{
#        X509   = $Cert
#        PEM    = $FormattedPem
#        RawPEM = $PemString
#    }
#
#    $PemResult
#}

# Converts the Azure style resource ID /tag1/value1/tag2/value2/tag3/value3 into a hash table
function Convert-AzResource2Hash
{
    Param( [Parameter(Mandatory=$true)][string]$AzResourceId )

    $AzHash = @{}
    $Pieces = $AzResourceId.Trim('/').Split('/')

    $i = 0
    do {
        $AzHash.Add($Pieces[$i],$Pieces[$i+1])
        $i += 2
    } while ($i -lt $Pieces.Count)

    $AzHash
}

# Search Application Gateway object for SSL Certificate by matching the ID
function Get-Ven2AzCertById
{
    Param(
        [Parameter(Mandatory=$true)][string]$CertificateId,
        [Parameter(Mandatory=$true)]$ApplicationGateway
    )

    foreach ($aCert in $ApplicationGateway.SslCertificates) {
        if ($aCert.Id -eq $CertificateId) {
            try {
                $Cert = Convert-Bytes2X509 -ByteString $aCert.PublicCertData
                return $Cert
            } catch {
                throw $_
            }
        }
    }
    
    Write-VenDebugLog "Certificate ID not found [$($CertificateId)]"
    throw "Certificate ID not found [$($CertificateId)]"
}

function Get-Ven2AzApplicationGateway
{
    Param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ResourceGroupName,
        [Parameter(Mandatory=$true)]$DefaultProfile
    )

    # How many times do we retry the application gateway search..?
    $maxRetries = 5

    # retrieve application gateway
    try {
        $i=0
        do {
            $AppGateway = Get-AzApplicationGateway -Name $Name -ResourceGroupName $ResourceGroupName -DefaultProfile $DefaultProfile
            if ($AppGateway -eq $null) {
                if ($i -ge $maxRetries) {
                    throw "AppGateway is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on $($AppGwName) Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($AppGateway -eq $null)
        Write-VenDebugLog "Found Application Gateway: $($AppGateway.Name)"
        Write-VenDebugLog "\\-- $($AppGateway.Id)"
    } catch {
        Write-VenDebugLog "Get-AzApplicationGateway has failed - $($_)"
        throw $_
    }
    $AppGateway
}

# Take a message, prepend a timestamp, output it to a debug log ... if DEBUG_FILE is set
# Otherwise do nothing and return nothing
function Write-VenDebugLog
{
    Param( [Parameter(Position=0, Mandatory)][string]$LogMessage )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # do nothing and return immediately if debug isn't on
    if ($DEBUG_FILE -eq $null) {
        return
    }
    
    # if the logfile isn't initialized then just crash now
    if ($Script:venDebugFile -eq $null) {
        throw("Call to Write-VenDebugLog() but logfile has not been initialized...")
    }

    # write the message to the debug file
    Write-Output "$($LogMessage)" | Add-TS | Add-Content -Path $Script:venDebugFile
}

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Mandatory)][String]$AppGW,
        [String]$Listener='ALL'
    )

    if ($Script:venDebugFile -ne $null) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($DEBUG_FILE -eq $null) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }
        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }
    else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))-$($AppGW)"
#    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))-$($AppGW)-$($Listener)"
    $Script:venDebugFile += ".log"
    
    Write-Output "" | Add-Content -Path $Script:venDebugFile
    Write-VenDebugLog "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"
}

# END OF SCRIPT