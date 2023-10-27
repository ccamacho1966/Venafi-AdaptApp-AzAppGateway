# Venafi-AdaptApp-AzAppGateway
Adaptable application driver for Azure application gateways that are NOT using Azure key vaults to manage certificates.

## Description
This adaptable application uses the Az PowerShell library to discover and manage certificates linked to Azure application gateways. This driver is not intended to manage key vaults, but rather to manage application gateways where the certificates are directly loaded into the application gateway configuration.

## Installation
Upload the adaptable log driver file 'Azure Application Gateway.ps1' to all Venafi servers.
The default folder location would be 'C:\Program Files\Venafi\Scripts\AdaptableApp'.

## Usage

### Credentials
Pass service principal credentials to the driver as a 'Username Credential' and linked either as the 'Device Credential' or 'Application Credential'. Use the SPID as the username and the KeyValue as the password.

### Policy-Level Application Fields
Debug This Driver (Yes/No) - Allows you to log debug info for all applications under this policy folder.
Azure Tenant ID - x
Azure Resource ID - x

### Device Configuration
Hostname/Address should be configured as the Azure resource ID for the application gateway. An application gateway resource ID should look like this:  
/subscriptions/123-456-789/resourceGroups/MyRG01/providers/Microsoft.Network/applicationGateways/MyAppGW01

### Application Configuration
You can either run an onboard discovery to populate all existing applications or manually create each application individually. If creating applications manually, you must supply the Azure tenant ID and listener name. The Azure resource ID is optional and for informational purposes only. Discovery will populate these fields automatically.
At this level, setting 'Debug This Driver' and 'Enable Debug Logging' function identically and will trigger log creation for this application.

## Support
Please report issues through github. This driver is still being actively used and supported.

## Roadmap
Functionally this should be 'complete' for discovery and management purposes. I will be releasing my application gateway discovery utility at a later date.

## Contributing
Assistance is always welcome. I'm not really a programmer. I just play one on community forums.

## Authors and acknowledgment
Just me for the moment. Buyer Beware.
