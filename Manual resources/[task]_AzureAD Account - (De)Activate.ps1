$userPrincipalName = $form.gridUsers.UserPrincipalName
$blnenabled = $form.enabled

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$verbosePreference = "SilentlyContinue"
$informationPreference = "Continue"

try{
   Write-Verbose "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    if($blnenabled -eq 'true'){
        #Change mapping here
        $account = [PSCustomObject]@{
            userPrincipalName = $userPrincipalName;
            accountEnabled = $true;
            showInAddressList = $true;
        }
        Write-Information "Enabling AzureAD user [$($account.userPrincipalName)].."
    }else{
        #Change mapping here
        $account = [PSCustomObject]@{
            userPrincipalName = $userPrincipalName;
            accountEnabled = $false;
            showInAddressList = $false;
        }
        Write-Information "Disabling AzureAD user [$($account.userPrincipalName)].."
    }

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

    if($blnenabled -eq 'true'){
        Write-Information "AzureAD user [$($account.userPrincipalName)] enabled successfully"
    }elseif($blnenabled -eq 'false'){
        Write-Information "AzureAD user [$($account.userPrincipalName)] disabled successfully"
    }
}catch{
    if($blnenabled -eq 'true'){
        Write-Error "Error enabling AzureAD user [$($account.userPrincipalName)]. Error: $_"
    }else{
        Write-Error "Error disabling AzureAD user [$($account.userPrincipalName)]. Error: $_"
    }
}
