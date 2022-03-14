$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$userPrincipalName = $form.gridUsers.UserPrincipalName
$blnenabled = $form.enabled

try {
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
    Write-Information "Found AD user [$userPrincipalName]"
} catch {
    Write-Error "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)"
}

if($blnenabled -eq 'true'){
    try {
    	$enableUser = Enable-ADAccount -Identity $adUser
    	
        Write-Information "Successfully enabled AD user [$userPrincipalName]"
    } catch {
        Write-Error "Could not enable AD user [$userPrincipalName]. Error: $($_.Exception.Message)"
    }
}
    
if($blnenabled -eq 'false'){
    try {
    	$disableUser = Disable-ADAccount -Identity $adUser
    	
        Write-Information "Successfully disabled AD user [$userPrincipalName]"
    } catch {
        Write-Error "Could not disable AD user [$userPrincipalName]. Error: $($_.Exception.Message)"
    }
}

