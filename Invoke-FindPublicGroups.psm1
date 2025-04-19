function Invoke-FindPublicGroup {
    param (
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken,

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string]$SecretId
    )

function Example{
        Write-Host "" 
        Write-Host "Hey F*ckers :)    " -ForegroundColor DarkCyan
        Write-Host "Usage:" -ForegroundColor DarkCyan
        Write-Host "" 
        Write-Host "    Invoke-FindPublicGroup -RefreshToken <Refresh_Token> " -ForegroundColor DarkCyan
        Write-Host "    Invoke-FindPublicGroup -ClientID <Application_ClientID> -SecretID <Application_SecretID> " -ForegroundColor DarkCyan
        Write-Host "" 

}

    if (-not $RefreshToken -and -not $ClientId -and -not $SecretId){
        Example
    }
    
    if ($ClientId -and -not $SecretId) {
        Write-Host "Needs SecretID" -DarkBlue 
    }
    
    if ($SecretId -and -not $ClientId) {
        Write-Host "Needs ClientId" -DarkBlue 
    }

    
    function Get-Token-WithRefreshToken {
        param ([string]$RefreshToken)
        $url = "https://login.microsoftonline.com/cef04b19-7776-4a94-b89b-375c77a8f936/oauth2/v2.0/token"
        $body = @{
            "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"         = "https://graph.microsoft.com/.default"
            "grant_type"    = "refresh_token"
            "refresh_token" = $RefreshToken
        }
        try {
            Write-Host "[*] Requesting access token using Refresh Token..." -ForegroundColor DarkYellow
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get token using refresh token: $_" -ForegroundColor Red
            return $null
        }
    }

    function Get-Token-WithClientSecret {
        param (
            [string]$ClientId,
            [string]$SecretId
        )
        $url = "https://login.microsoftonline.com/cef04b19-7776-4a94-b89b-375c77a8f936/oauth2/v2.0/token"
        $body = @{
            "client_id"     = $ClientId
            "client_secret" = $SecretId
            "scope"         = "https://graph.microsoft.com/.default"
            "grant_type"    = "client_credentials"
        }
        try {
            Write-Host "[*] Requesting access token using Client Credentials..." -ForegroundColor DarkYellow
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get token using client credentials: $_" -ForegroundColor Red
            return $null
        }
    }

   
    $authMethod = ""
    if ($RefreshToken) {
        $authMethod = "refresh"
        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
    } elseif ($ClientId -and $SecretId) {
        $authMethod = "client"
        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
    } else {
       # Write-Host "[-] No authentication method provided." -ForegroundColor Red
        return
    }

    if (-not $GraphAccessToken) {
        Write-Host "[-] Failed to acquire initial Access Token." -ForegroundColor Red
        return
    }
    
    if (Test-Path "public_groups.txt") {
        $choice = Read-Host "File 'public_groups.txt' already exists. Do you want to (D)elete it or (A)ppend to it? [D/A]" 
        if ($choice -eq "D" -or $choice -eq "d") {
            Remove-Item -Path "public_groups.txt" -Force
            Write-Host "[*] Deleted existing 'public_groups.txt'. Starting fresh." -ForegroundColor DarkYellow
        } elseif ($choice -eq "A" -or $choice -eq "a") {
            Write-Host "[*] Appending to existing 'public_groups.txt'..." -ForegroundColor DarkYellow
        } else {
            Write-Host "[-] Invalid choice. Exiting." -ForegroundColor Red
            return
        }
    }

    # Headers
    $headers = @{
        "Authorization"    = "Bearer $GraphAccessToken"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "eventual"
        "Prefer"           = "odata.maxpagesize=999" #Importentttttttt!!!
    }

    $startTime = Get-Date
    $refreshIntervalMinutes = 7 #every 7 min the script will request new access token :)!!!!
    $allowedGroupIds = @()
    $groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$top=999"
    $estimateUrl = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"

    do {
        try {
            $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get
        } catch {
            Write-Host "[-] Failed to fetch groups: $_" -ForegroundColor DarkRed
            break
        }

        foreach ($group in $response.value) {
            if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
                Write-Host "[*] Token refresh interval reached. Requesting new token..." -ForegroundColor DarkYellow
                if ($authMethod -eq "refresh") {
                    $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                } elseif ($authMethod -eq "client") {
                    $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                }
                if (-not $GraphAccessToken) {
                    Write-Host "[-] Failed to refresh Access Token." -ForegroundColor Red
                    return
                }
                $headers["Authorization"] = "Bearer $GraphAccessToken"
                $startTime = Get-Date
            }

            $groupId = $group.id
            $groupDisplayName = $group.displayName
            $body = @{
                resourceActionAuthorizationChecks = @(
                    @{
                        resourceAction   = "microsoft.directory/groups/members/update"
                        directoryScopeId = "/$groupId"
                    }
                )
            } | ConvertTo-Json -Depth 3

            $success = $false
            do {
                try {
                    $responseEstimate = Invoke-RestMethod -Uri $estimateUrl -Headers $headers -Method Post -Body $body
                    if ($responseEstimate.value.accessDecision -eq "Allowed") {
                        Write-Host "[+] $groupDisplayName ($groupId) is Public." -ForegroundColor Green
                        $line = $groupDisplayName.PadRight(30) + ":         " + $groupId #changed
                        $allowedGroupIds += $line #added
                        Add-Content -Path "public_groups.txt" -Value $line #added
                    } else {
                        Write-Host "[-] $groupDisplayName ($groupId) is not Public." -ForegroundColor DarkGray
                    }
                    $success = $true
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } elseif ($statusCode -eq 401) {
                        Write-Host "[!] Access Token expired. Refreshing..." -ForegroundColor DarkYellow
                        if ($authMethod -eq "refresh") {
                            $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                        } elseif ($authMethod -eq "client") {
                            $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                        }
                        if (-not $GraphAccessToken) {
                            Write-Host "[-] Failed to refresh Access Token." -ForegroundColor Red
                            return
                        }
                        $headers["Authorization"] = "Bearer $GraphAccessToken"
                        $startTime = Get-Date
                    } else {
                        Write-Host "[-] Error checking group $groupDisplayName ($groupId)" -ForegroundColor DarkRed
                        $success = $true
                    }
                }
            } while (-not $success)

            Start-Sleep -Milliseconds 50
        }

        $groupApiUrl = $response.'@odata.nextLink'
    } while ($groupApiUrl)

    #$allowedGroupIds | Out-File -FilePath "public_groups.txt" -Encoding ascii
    Write-Host "`n[*] Saved $($allowedGroupIds.Count) Public group IDs to public_groups.txt" -ForegroundColor DarkCyan

    return $allowedGroupIds
}
