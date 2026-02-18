# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$userPrincipalName = $form.gridUsers.UserPrincipalName
$id = $form.gridUsers.Id
$blnenabled = $form.enabled

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
	
	# Extract the private key from the certificate
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

try {
    Write-Verbose "Generating Microsoft Graph API Access Token.."

    # Setup Connection with Entra/Exo
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $entraToken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    } 

    if ($blnenabled -eq 'true') {
        #Change mapping here
        $account = [PSCustomObject]@{
            id                = $id
            userPrincipalName = $userPrincipalName
            accountEnabled    = $true
            #showInAddressList = $true
        }
        Write-Information "Enabling EntraID user [$($account.userPrincipalName) ($($account.id))].."
    }
    else {
        #Change mapping here
        $account = [PSCustomObject]@{
            id                = $id
            userPrincipalName = $userPrincipalName
            accountEnabled    = $false
            #showInAddressList = $false
        }
        Write-Information "Disabling EntraID user [$($account.userPrincipalName) ($($account.id))].."
    }

    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

    if ($blnenabled -eq 'true') {
        Write-Information "EntraID user [$($account.userPrincipalName) ($($account.id))] enabled successfully"
        
        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "EntraID user [$($account.userPrincipalName) ($($account.id))] enabled successfully" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
    elseif ($blnenabled -eq 'false') {
        Write-Information "EntraID user [$($account.userPrincipalName) ($($account.id))] disabled successfully"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "EntraID user [$($account.userPrincipalName) ($($account.id))] enabled successfully" # required (free format text) 
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
        Write-Error "Error enabling EntraID user [$($account.userPrincipalName) ($($account.id))]. Error: $_"

        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Failed to enable EntraID user [$($account.userPrincipalName) ($($account.id))]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
    else {
        Write-Error "Error disabling EntraID user [$($account.userPrincipalName) ($($account.id))]. Error: $_"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Failed to disable EntraID user [$($account.userPrincipalName) ($($account.id))]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($account.userPrincipalName) # optional (free format text) 
            TargetIdentifier  = $([string]$id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }
}
