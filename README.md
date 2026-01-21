# HelloID-Conn-SA-Full-EntraID-Account-De-Activate

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
HelloID-Conn-SA-Full-EntraID-Account-De-Activate is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can manage resource attributes across your connected systems. The following options are available:
 1. Search and select the resource
 2. Enter new values for the resource attributes
 3. The entered values are validated
 4. Resource attributes are updated with new values across connected systems
 5. Writing back values will be handled according to system-specific rules and configurations

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID, an App Registration. During the setup process, you’ll create a new App Registration in the Entra portal, assign the necessary API permissions (such as user and group read/write), and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All`
  - `User.EnableDisableAccount.All`
  - `User-PasswordProfile.ReadWrite.All`
  - `User-Phone.ReadWrite.All`
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following user-defined variables are used by the connector.

| Setting     | Description                              | Mandatory |
| ----------- | ---------------------------------------- | --------- |
| EntraTenantId | Entra tenant ID                       | Yes       |
| EntraAppId    | Entra application (client) ID         | Yes       |
| EntraCertificateBase64String | Entra Certificate string      | Yes       |
| EntraCertificatePassword | Entra Certificate password      | Yes       |

## Remarks

### User Lookup by ID
- Uses the Entra ID user `id` for correlation and updates, rather than `userPrincipalName`, to avoid issues with renames or alternate sign-in IDs.

### Updating `accountEnabled`
- Enabling or disabling a user is performed via a PATCH to the user resource setting `accountEnabled` to `true` or `false`.

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint              | Description                                  |
| --------------------- | -------------------------------------------- |
| /users                | Search and retrieve users                     |
| /users/{id}           | Retrieve a specific user                      |
| /users/{id} (PATCH)   | Update a user (e.g., `accountEnabled`)        |

### API documentation

- Microsoft Graph overview: https://learn.microsoft.com/graph/
- Update user (accountEnabled): https://learn.microsoft.com/graph/api/user-update

## Getting help
> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our documentation pages: https://docs.helloid.com/en/service-automation/delegated-forms.html

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
