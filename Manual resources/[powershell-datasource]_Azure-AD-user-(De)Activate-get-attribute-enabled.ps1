# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $datasource.selectedUser.UserPrincipalName

    Write-Information "Generating Microsoft Graph API Access Token.."

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
         
    Write-Information "Searching for AzureAD user userPrincipalName=$userPrincipalName"

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $properties = @("accountEnabled")
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    Write-Information "Finished searching AzureAD user [$userPrincipalName]"

    $enabled = $azureADUser.accountEnabled
     
    Write-Information "Account enabled: $enabled"
     
    $returnObject = [Ordered]@{
        enabled = $enabled
    }

    Write-Output $returnObject
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $_" + $errorDetailsMessage)
}
