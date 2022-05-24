#
# Azure AppGW - An Adaptable Application Driver for Venafi
#
# Template Driver Version: 202006081054
$Script:AdaptableAppVer = "202205241115"
$Script:AdaptableAppDrv = "Azure AppGW"

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

##### Azure Tenant ID   - REQUIRED: This should be paired with the credential, but...
##### Listener Name     - REQUIRED: Maps application to Azure Listener, i.e. 'MyAGW'
##### Azure Resource ID - Populated by discovery as a courtesy reference

Thoughts on limitations...
* restrict to OperationalState=Running and ProvisioningState=Succeeded ..?

#>

#
# The following 3 functions are required only for remote key generation support.
# If commented out, the driver will assume this feature is not supported.
#

# REMOTE KEY GENERATION SUPPORT DISABLED

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

    Initialize-VenDebugLog -General $General

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $General.VarText1.Trim()
    $LocalHost = [Environment]::MachineName
    
    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"

    try {
        $TempPfxFile = New-TemporaryFile
    } catch {
        throw "$($LocalHost): TempFile creation failed: ($($_))"
    }

    Write-VenDebugLog "PFX filename:        [$($TempPfxFile.FullName)]"
#    Write-VenDebugLog "PFX password:        [$($Specific.EncryptPass)]"

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
            Write-VenDebugLog "Chain Entity #$($i): $($Cert.GetNameInfo(0,$false))"
#            Write-VenDebugLog "\\-- Subject $($Cert.Subject)"
#            Write-VenDebugLog "\\-- Serial Number $($Cert.SerialNumber)"
#            Write-VenDebugLog "\\-- Thumbprint $($Cert.Thumbprint)"
        }
    }
    catch {
        throw "$($LocalHost): Invalid certificate: ($($_))"
    }

    try {
        [IO.File]::WriteAllBytes($TempPfxFile.FullName,$Specific.Pkcs12)
    }
    catch {
        throw "$($LocalHost): Certificate export failed: ($($_))"
    }

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($null -eq $AzContext) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on AzContext Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($null -eq $AzContext)
    }
    catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    }
    catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    try {
        # check to see if certificate is already defined
        $AzSslCert = Get-AzApplicationGatewaySslCertificate -Name $General.AssetName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        if ($null -eq $AzSslCert) {
            # doesn't exist - need to upload the certificate
            Write-VenDebugLog "Uploading certificate $($General.AssetName) to $($AppGwName)"
            $PfxPW = ConvertTo-SecureString $Specific.EncryptPass -AsPlainText -Force
            $AppGateway = Add-AzApplicationGatewaySslCertificate -ApplicationGateway $AppGateway -Name $General.AssetName -CertificateFile $TempPfxFile.FullName -Password $PfxPW -DefaultProfile $AzContext
            $AzSslCert = Get-AzApplicationGatewaySslCertificate -Name $General.AssetName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
            if ($null -eq $AzSslCert) {
                Write-VenDebugLog "Newly uploaded certificate not found!"
                throw "Can't find uploaded cert"
            }
            Write-VenDebugLog "SSL certificate $($General.AssetName) has been uploaded successfully"
        }
        else {
            # certificate has already been uploaded to the application gateway
            Write-VenDebugLog "SSL certificate $($AzSslCert.Name) is already installed"
#            Convert-Bytes2X509 $AzSslCert.PublicCertData
#            $ExistingCert = Convert-Bytes2X509 -ByteString $AzSslCert.PublicCertData
#            Write-VenDebugLog "\\-- Subject $($ExistingCert.X509.Subject)"
#            Write-VenDebugLog "\\-- Serial Number $($ExistingCert.X509.SerialNumber)"
#            Write-VenDebugLog "\\-- Thumbprint $($ExistingCert.X509.Thumbprint)"
            # Consider implementing logic to validate correct cert is installed..?
            Write-VenDebugLog "Certificate Already Exists - Returning control to Venafi TPP"
            return @{ Result="AlreadyInstalled"; }
        }
    }
    catch {
        throw "Error looking for existing cert - $($_)"
    }

    # save new certificate to application gateway configuration
    try {
        Write-VenDebugLog "Saving updated configuration for $($AppGwName)"
        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzContext #-Verbose *>> $Script:V2Afile
        if ($null -eq $AppGateway) {
            Write-VenDebugLog "Configuration update FAILED! (AGW is NULL)"
            throw "Updated AGW is NULL"
        }
    }
    catch {
        Write-VenDebugLog "Configuration update FAILED! $($_)"
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

    Initialize-VenDebugLog -General $General

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $General.VarText1.Trim()
    $LocalHost = [Environment]::MachineName

    $CertName = $General.AssetName
    
    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"
    Write-VenDebugLog "Certificate Name:    [$($CertName)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($null -eq $AzContext) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                } else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss #$($i) on AzContext Sub:$($SubscriptionID) () - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($null -eq $AzContext)
    }
    catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    }
    catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    # retrieve http listener
    try {
        $Listener = Get-AzApplicationGatewayHttpListener -Name $ListenerName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found Listener: $($ListenerName)"
#        Write-VenDebugLog "\\-- $($Listener.Id)"
    }
    catch {
        Write-VenDebugLog "Get-AzApplicationGatewayHttpListener has failed - $($_)"
        throw "$($LocalHost): Get-AzApplicationGatewayHttpListener has failed - $($_)"
    }

    # retrieve installed certificate information
    try {
        $AzCertificate = Get-AzApplicationGatewaySslCertificate -Name $CertName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found SSL Certificate: $($CertName)"
#        Write-VenDebugLog "\\-- $($AzCertificate.Id)"
    }
    catch {
        Write-VenDebugLog "Get-AzApplicationGatewaySslCertificate has failed - $($_)"
        throw "$($LocalHost): Get-AzApplicationGatewaySslCertificate has failed - $($_)"
    }

    $OldSslCert = Convert-AzResource2Hash -AzResourceId $Listener.SslCertificate.Id
    Write-VenDebugLog "Replacing SSL Certificate: $($OldSslCert['sslCertificates'])"
#    Write-VenDebugLog "\\-- $($Listener.SslCertificate.Id)"

    try {
        $ListenerHash = @{
            Name = $ListenerName
            FrontendIPConfigurationId = $Listener.FrontendIpConfiguration.Id
            FrontendPortId = $Listener.FrontendPort.Id
            SslCertificateId = $AzCertificate.Id
            RequireServerNameIndication = $Listener.RequireServerNameIndication
            Protocol = $Listener.Protocol
        }
        if ($null -ne $Listener.FirewallPolicy) {
            $ListenerHash.Add('FirewallPolicyId',$Listener.FirewallPolicy.Id)
        }
        if ($null -ne $Listener.HostName) {
            $ListenerHash.Add('HostName',$Listener.HostName)
        }
        #
        # CustomErrorConfigurations and/or HostNames can be non-null but have 0 entries.
        # This will be rejected by the Azure API so now we validate 1 or more entries exists.
        #
        # The argument is null, empty, or an element of the argument collection contains a null value.
        # Supply a collection that does not contain any null values and then try the command again.
        #
        if (($null -ne $Listener.HostNames) -and ($Listener.HostNames.Count -ge 1)) {
            $ListenerHash.Add('HostNames',$Listener.HostNames)
        }
        if (($null -ne $Listener.CustomErrorConfigurations) -and ($Listener.CustomErrorConfigurations.Count -ge 1)) {
            $ListenerHash.Add('CustomErrorConfiguration',$Listener.CustomErrorConfigurations)
        }
        $AppGateway = Set-AzApplicationGatewayHttpListener -ApplicationGateway $AppGateway @ListenerHash -DefaultProfile $AzContext
    }
    catch {
        Write-VenDebugLog "Set-AzApplicationGatewayHttpListener has failed - $($_)"
        throw "$($LocalHost): Set-AzApplicationGatewayHttpListener has failed - $($_)"
    }

    try {
        $AppGateway = Set-AzApplicationGateway -ApplicationGateway $AppGateway -DefaultProfile $AzContext
    }
    catch {
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

    Initialize-VenDebugLog -General $General

    $ListenerName = $General.VarText4.Trim()
    $AzSpPass = $General.UserPass

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $TenantID = $General.VarText1.Trim()
    
    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"
    Write-VenDebugLog "Listener Name:       [$($ListenerName)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($null -eq $AzContext) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                }
                else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss #$($i) on AzContext Sub:$($SubscriptionID) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($null -eq $AzContext)
    }
    catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    }
    catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    # retrieve https listener
    try {
        $Listener = Get-AzApplicationGatewayHttpListener -Name $ListenerName -ApplicationGateway $AppGateway -DefaultProfile $AzContext
        Write-VenDebugLog "Found Listener: $($Listener.Name)"
#        Write-VenDebugLog "\\-- $($Listener.Id)"
    }
    catch {
        Write-VenDebugLog "Get-AzApplicationGatewayHttpListener call failed - $($_)"
        throw $_
    }

    # retrieve certificate data
    Write-VenDebugLog 'Searching for SSL Certificate...'
#    Write-VenDebugLog "\\-- $($Listener.SslCertificate.Id)"
    try {
        $Cert = Get-Ven2AzCertById -CertificateId $Listener.SslCertificate.Id -ApplicationGateway $AppGateway
    }
    catch {
        Write-VenDebugLog "SSL certificate not found for Listener $($ListenerName)"
        throw "SSL certificate not found for Listener $($ListenerName)"
    }
#    Write-VenDebugLog "Certificate Subject:       $($Cert.X509.Subject)"
#    Write-VenDebugLog "Certificate Serial Number: $($Cert.X509.SerialNumber)"
#    Write-VenDebugLog "Certificate Thumbprint:    $($Cert.X509.Thumbprint)"

    Disconnect-Ven2Azure

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

    $started=Get-Date

    if ($General.HostAddress.Trim() -notlike '/?*/?*') {
        return @{ Result = "NotUsed"; }
    }

    Initialize-VenDebugLog -General $General

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $SubscriptionID = $AzHash['subscriptions']
    $ResourceGroup = $AzHash['resourceGroups']
    $AppGwName = $AzHash['applicationGateways']

    $AzUser = $General.UserName.Trim().Split('@')
    $AzSpName = $AzUser[0]
    $AzSpPass = $General.UserPass
    $TenantID = $General.VarText1.Trim()

    Write-VenDebugLog "Tenant ID:           [$($TenantID)]"
    Write-VenDebugLog "Subscription ID:     [$($SubscriptionID)]"
    Write-VenDebugLog "Resource Group:      [$($ResourceGroup)]"
    Write-VenDebugLog "Application Gateway: [$($AppGwName)]"

    # connect to Azure API
    try {
        $AzProfile = Connect-Ven2Azure -AppId $AzSpName -AppPw $AzSpPass -TenantId $TenantID -SubscriptionId $SubscriptionID
        $i=0
        do {
            $AzContext = Set-AzContext -Subscription $SubscriptionID -Scope Process
            if ($null -eq $AzContext) {
                if ($i -ge 5) {
                    throw "AzContext is NULL"
                }
                else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss #$($i) on AzContext Sub:$($SubscriptionID) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($null -eq $AzContext)
    }
    catch {
        Write-VenDebugLog "Connect-Ven2AzGateway call failed - $($_)"
        throw $_
    }

    # retrieve application gateway
    try {
        $AppGateway = Get-Ven2AzApplicationGateway -Name $AppGwName -ResourceGroupName $ResourceGroup -DefaultProfile $AzContext
    }
    catch {
        Write-VenDebugLog "Get-Ven2AzApplicationGateway has failed - $($_)"
        throw $_
    }

    $ApplicationList = @()
    foreach ($aListener in $AppGateway.HttpListeners) {
        if ($aListener.Protocol -eq 'Https') {
            if ($aListener.SslCertificate.Id -ne '') {
                Write-VenDebugLog "Discovered: Https Listener [$($aListener.Name)]"
#                Write-VenDebugLog "\\-- Cert [$($aListener.SslCertificate.Id)]"
                try {
                    $Cert = Get-Ven2AzCertById -CertificateId $aListener.SslCertificate.Id -ApplicationGateway $AppGateway
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
                }
                catch {
                    Write-VenDebugLog "Ignored: Listener [$($aListener.Name)] has no certificate"
                }
            }
        }
        else {
            Write-VenDebugLog "Ignored: Listener [$($aListener.Name)] is unencrypted"
        }
    }

    Disconnect-Ven2Azure

    Write-VenDebugLog "Discovered $($ApplicationList.Count) Listeners on Application Gateway $($AppGateway.Name)"

    $finished = Get-Date
    $runtime = New-TimeSpan -Start $started -End $finished
    Write-VenDebugLog "Scanned $($AppGateway.HttpListeners.Count) listeners (Runtime $($runtime)) - Returning control to Venafi"

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

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

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
    }
    catch {
        Write-VenDebugLog "Connect-AzAccount has failed - $($_)"
        throw $_
    }

    $SpProfile
}

function Disconnect-Ven2Azure
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    Write-VenDebugLog "Disconnecting from Azure API"
    Disconnect-AzAccount
}

Function Convert-Bytes2X509
{
    Param( [Parameter(Mandatory=$true,Position=0)][string]$ByteString )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $CertBytes = [Convert]::FromBase64String($ByteString)
    Add-Type -AssemblyName System.Security
    $P7B = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $P7B.Decode($CertBytes)

    Write-VenDebugLog "Bundle contains $($P7B.Certificates.Count) certificates"
    
    $CertOrder = @()
    if ($P7B.Certificates.Count -eq 1) {
        # Only 1 certificate so use that one
        $ServerAt=0
        $CertOrder += $ServerAt
    }
    else {
        # find the self-signed root certificate first
        $i=0
        foreach ($aCert in $P7B.Certificates) {
            $CertCN = $aCert.GetNameInfo(0,$false)
            $Issuer = $aCert.GetNameInfo(0,$true)
            if ($CertCN -eq $Issuer) {
                Write-VenDebugLog "Selecting certificate #$($i+1) as ROOT: $($CertCN)"
#                Write-VenDebugLog "\\-- ROOT: Subject:       $($aCert.Subject)"
#                Write-VenDebugLog "\\-- ROOT: Serial Number: $($aCert.SerialNumber)"
#                Write-VenDebugLog "\\-- ROOT: Thumbprint:    $($aCert.Thumbprint)"
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
                    }
                    else {
                        # this is the server cert
                        $ServerAt=$i
                        $CertType='SERVER'
                    }
                    $CertCN = $aCert.GetNameInfo(0,$false)
                    $Issuer = $aCert.GetNameInfo(0,$true)
                    Write-VenDebugLog "Selecting certificate #$($i+1) as $($CertType): $($CertCN)"
#                    Write-VenDebugLog "\\-- $($CertType): Subject:       $($aCert.Subject)"
#                    Write-VenDebugLog "\\-- $($CertType): Issuer:        $($Issuer)"
#                    Write-VenDebugLog "\\-- $($CertType): Serial Number: $($aCert.SerialNumber)"
#                    Write-VenDebugLog "\\-- $($CertType): Thumbprint:    $($aCert.Thumbprint)"
                    break    # end this foreach iteration
                }
                $i++
                if ($i -ge $P7B.Certificates.Count) {
                    # that's bad... certificate we couldn't place in the chain. time to die.
                    Write-VenDebugLog "FATAL ERROR! Could not sort certificate chain."
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
    }
    else {
        $RootResults = $null
    }

    Write-VenDebugLog "Returning certificate #$($ServerAt+1) to $((Get-PSCallStack)[1].Command)"

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

# Converts the Azure style resource ID /tag1/value1/tag2/value2/tag3/value3 into a hash table
function Convert-AzResource2Hash
{
    Param( [Parameter(Mandatory=$true)][string]$AzResourceId )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

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

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    foreach ($aCert in $ApplicationGateway.SslCertificates) {
        if ($aCert.Id -eq $CertificateId) {
            try {
                $Cert = Convert-Bytes2X509 -ByteString $aCert.PublicCertData
                return $Cert
            }
            catch {
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

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    # How many times do we retry the application gateway search..?
    $maxRetries = 5

    # retrieve application gateway
    try {
        $i=0
        do {
            $AppGateway = Get-AzApplicationGateway -Name $Name -ResourceGroupName $ResourceGroupName -DefaultProfile $DefaultProfile
            if ($null -eq $AppGateway) {
                if ($i -ge $maxRetries) {
                    throw "AppGateway is NULL ($($maxRetries) attempts)"
                }
                else {
                    $i++
                    $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
                    Write-VenDebugLog "...miss on $($AppGwName) Sub:$($AzContext.Subscription) (#$($i)) - sleeping for $($wait) seconds"
                    Start-Sleep -Seconds $wait
                }
            }
        } while ($null -eq $AppGateway)
        Write-VenDebugLog "Found Application Gateway: $($AppGateway.Name)"
#        Write-VenDebugLog "\\-- $($AppGateway.Id)"
    }
    catch {
        Write-VenDebugLog "Get-AzApplicationGateway has failed - $($_)"
        throw $_
    }
    $AppGateway
}

# Take a message, prepend a timestamp, output it to a debug log ... if DEBUG_FILE is set
# Otherwise do nothing and return nothing
function Write-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory)][string]$LogMessage,
        [switch]$NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # if the logfile isn't initialized then do nothing and return immediately
    if ($null -eq $Script:venDebugFile) { return }

    if ($NoFunctionTag.IsPresent) {
        $taggedLog = $LogMessage
    }
    else {
        $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
    }

    # write the message to the debug file
    Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile
}

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory)][System.Collections.Hashtable]$General
    )

    if ($null -ne $Script:venDebugFile) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($null -eq $DEBUG_FILE) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }
        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }
    else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    $AzHash = Convert-AzResource2Hash $General.HostAddress.Trim()
    $AppGw = $AzHash['applicationGateways']

    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))-$($AppGW).log"
    
    Write-Output "" | Add-Content -Path $Script:venDebugFile
    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"
}

# END OF SCRIPT