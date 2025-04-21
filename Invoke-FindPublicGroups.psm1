function Invoke-FindPublicGroups {
    param (
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken,

        [Parameter(Mandatory = $false)]
        [switch]$DeviceCodeFlow,

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string]$SecretId
    )

    function Example {
        Write-Host "`nHey F*ckers" -ForegroundColor DarkYellow
        Write-Host "Usage:" -ForegroundColor DarkYellow
        Write-Host "------------" -ForegroundColor DarkYellow
        Write-Host "Invoke-FindPublicGroups -DeviceCodeFlow" -ForegroundColor DarkCyan
        Write-Host "Invoke-FindPublicGroups -RefreshToken <Refresh_Token>" -ForegroundColor DarkCyan
        Write-Host "Invoke-FindPublicGroups -ClientId <Application_ClientID> -SecretId <Application_SecretID>" -ForegroundColor DarkCyan
    }

    if (-not $RefreshToken -and -not $ClientId -and -not $SecretId -and -not $DeviceCodeFlow) {
        Example
        return
    }

    function Get-DeviceCodeToken {
        $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
        $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://graph.microsoft.com/.default"
        }
        $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $body
        $code = $authResponse.user_code
        $deviceCode = $authResponse.device_code
        Write-Host "`n[*] Open browser and enter code:" -ForegroundColor DarkCyan -NoNewline
        Write-Host " $code" -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
        Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

        $tokenUrl = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
        $tokenBody = @{
            "scope"      = "openid"
            "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code"       = $deviceCode
        }

        while ($true) {
            try {
                $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop
                return $tokenResponse.refresh_token
            } catch {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorResponse.error -eq "authorization_pending") {
                    Start-Sleep -Seconds 5
                } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                    return $null
                } else {
                    return $null
                }
            }
        }
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
        return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
    }

    function Get-Token-WithClientSecret {
        param ([string]$ClientId, [string]$SecretId)
        $url = "https://login.microsoftonline.com/cef04b19-7776-4a94-b89b-375c77a8f936/oauth2/v2.0/token"
        $body = @{
            "client_id"     = $ClientId
            "client_secret" = $SecretId
            "scope"         = "https://graph.microsoft.com/.default"
            "grant_type"    = "client_credentials"
        }
        return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
    }

    
    $authMethod = ""
    if ($RefreshToken) {
        $authMethod = "refresh"
        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
    } elseif ($ClientId -and $SecretId) {
        $authMethod = "client"
        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
    } elseif ($DeviceCodeFlow) {
	$authMethod = "refresh"
         if (Test-Path "C:\Users\Public\RefreshToken.txt"){
             Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
	$RefreshToken = Get-DeviceCodeToken
	Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
	Write-Host "[FOR YOU BABY] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
    }

    if (-not $GraphAccessToken) { return }

    if (Test-Path "Public_Groups.txt") {
        $choice = Read-Host "Public_Groups.txt exists. (D)elete / (A)ppend?"
        if ($choice -match "^[dD]$") {
            Remove-Item -Path "Public_Groups.txt" -Force
        } elseif ($choice -notmatch "^[aA]$") {
            return
        }
    }

    $headers = @{
        "Authorization"    = "Bearer $GraphAccessToken"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "eventual"
        "Prefer"           = "odata.maxpagesize=999"
    }

    $startTime = Get-Date
    $refreshIntervalMinutes = 7
    $groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility&$top=999"

    $totalGroupsScanned = 0

    Write-Host "`n[*] Fetching Public Groups..." -ForegroundColor DarkCyan

    do {
        $success = $false
        do {
            try {
                $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get -ErrorAction Stop
                $success = $true
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 7 }
                    Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } elseif ($statusCode -eq 401) {
                    Write-Host "[!] Access token expired, refreshing..." -ForegroundColor DarkYellow
                    if ($authMethod -eq "refresh") {
                        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                    } elseif ($authMethod -eq "client") {
                        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                    }
                    if (-not $GraphAccessToken) { return }
                    $headers["Authorization"] = "Bearer $GraphAccessToken"
                    $startTime = Get-Date
                } else {
                    Write-Host "[-] Unexpected error. Exiting." -ForegroundColor Red
                    return
                }
            }
        } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0

        foreach ($group in $groupsBatch) {
            $groupId = $group.id
            $groupName = $group.displayName
            $visibility = $group.visibility

            if ($visibility -eq "Public") {
                Write-Host "[+] $groupName ($groupId) is Public" -ForegroundColor DarkGreen
                "$($groupName.PadRight(30)) : $($groupId.PadRight(40))" | Add-Content -Path "Public_Groups.txt"
            } else {
                
            }

            $scannedInBatch++
            $totalGroupsScanned++
            $percent = [math]::Round(($scannedInBatch / $batchCount) * 100)
            Write-Progress -Activity "Scanning Public Groups..." -Status "$percent% Complete in current batch" -PercentComplete $percent
        }

        if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
            Write-Host "[*] Refresh interval reached, refreshing token..." -ForegroundColor DarkYellow
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
            } elseif ($authMethod -eq "client") {
                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
            }
            if (-not $GraphAccessToken) { return }
            $headers["Authorization"] = "Bearer $GraphAccessToken"
            $startTime = Get-Date
        }

        $groupApiUrl = $response.'@odata.nextLink'

    } while ($groupApiUrl)

    Write-Host "`n[*] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
}
