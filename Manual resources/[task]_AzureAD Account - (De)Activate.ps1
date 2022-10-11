# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$userPrincipalName = $form.gridUsers.UserPrincipalName
$id = $form.gridUsers.Id
$blnenabled = $form.enabled

try {
    Write-Verbose "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token

    if ($blnenabled -eq 'true') {
        #Change mapping here
        $account = [PSCustomObject]@{
            id                = $id
            userPrincipalName = $userPrincipalName
            accountEnabled    = $true
            showInAddressList = $true
        }
        Write-Information "Enabling AzureAD user [$($account.userPrincipalName) ($($account.id))].."
    }
    else {
        #Change mapping here
        $account = [PSCustomObject]@{
            id                = $id
            userPrincipalName = $userPrincipalName
            accountEnabled    = $false
            showInAddressList = $false
        }
        Write-Information "Disabling AzureAD user [$($account.userPrincipalName) ($($account.id))].."
    }

    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

    if ($blnenabled -eq 'true') {
        Write-Information "AzureAD user [$($account.userPrincipalName) ($($account.id))] enabled successfully"
        
        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "AzureAD user [$($account.userPrincipalName) ($($account.id))] enabled successfully" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
    elseif ($blnenabled -eq 'false') {
        Write-Information "AzureAD user [$($account.userPrincipalName) ($($account.id))] disabled successfully"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "AzureAD user [$($account.userPrincipalName) ($($account.id))] enabled successfully" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
}
catch {
    if ($blnenabled -eq 'true') {
        Write-Error "Error enabling AzureAD user [$($account.userPrincipalName) ($($account.id))]. Error: $_"

        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Failed to enable AzureAD user [$($account.userPrincipalName) ($($account.id))]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
    else {
        Write-Error "Error disabling AzureAD user [$($account.userPrincipalName) ($($account.id))]. Error: $_"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Failed to disable AzureAD user [$($account.userPrincipalName) ($($account.id))]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
}
