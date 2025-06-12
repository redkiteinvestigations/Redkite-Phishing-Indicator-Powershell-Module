function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [ValidateSet("INFO", "WARN", "ALERT", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    Write-Host $logEntry
}

function Test-RequiredModules {
    param (
        [string[]]$Modules
    )

    foreach ($module in $Modules) {
        Write-Host "Checking module '$module'..."

        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-Host "Module '$module' is NOT installed." -ForegroundColor Yellow

            # Prompt user for installation
            $install = Read-Host "Module '$module' is required. Would you like to install it now? (Y/N)"
            if ($install -match '^[Yy]') {
                try {
                    # Check if NuGet provider is available
                    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                        Write-Host "NuGet provider not found. Installing NuGet provider..."
                        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
                    }

                    # Install module
                    Write-Host "Installing module '$module'..."
                    Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                    Write-Host "Module '$module' installed successfully." -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to install module '$module': $($_.Exception.Message)"
                    return
                }
            }
            else {
                Write-Host "Please install the module manually using 'Install-Module $module -Scope CurrentUser'." -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host "Module '$module' is installed." -ForegroundColor Green

            $imported = Get-Module -Name $module
            if (-not $imported) {
                Write-Host "Importing module '$module'..."
                Import-Module $module -Force
                Write-Host "Module '$module' imported successfully." -ForegroundColor Green
            }
            else {
                Write-Host "Module '$module' is already imported." -ForegroundColor Cyan
            }
        }
    }
    
    

    Write-Host "All module requirements met." -ForegroundColor Green
    Write-Host ""
    Write-Host "Type 'Start-Redkite' when ready." -ForegroundColor Yellow
}


# Run this check before starting the main script
Test-RequiredModules -Modules @('Microsoft.Graph.Users', 'ExchangeOnlineManagement')



function Start-Redkite {

    [CmdletBinding()]
    param ()
	Write-Host @"

                                                                       
        #                                                              
      ###### ##                                                        
   ####  ########                                                
   ##  ############                                                   
      #######     ####          ================================================                                    
       ###   ###########         Welcome to RedKite Phishing Indicators Checker                                   
         ###      ########      ================================================                                     
           ######   #######                                            
             ###### #########                                          
              # ##  ##########                                         
               #################                                       
                 ################   ##                                 
                  ##############   ####                                
                    ##### #####  ######                                
                     ######### ###########                             
                       ###### ################                         
                         ### #######################                   
                            ###########################                
                        #### ############################              
                      #################### ## ##############           
                   #############  ############      ####  #####        
                ######## ##### #     ############# #       ####        
               ## ####### #  ###         ######### ##   # #### ###     
                       #####  ##                 ## #      #####  #    
                         #### #                    ##### # #### ##     
                           ####                         # #### #  ##   
                             ##                              ## ##     
                             ##                                #  #    
                                                                       
 
"@ -ForegroundColor Red
Start-Sleep -Seconds 2  # Pause for 2 seconds
    
    Write-Host " "
    Write-Host "This tool is designed to check ExchangeOnline for common indicators of compromised accounts."
    Write-Host "The checks focus on email phishing attacks; looking at commonly used inbox rules and external re-directs."
    Write-Host " "
    Write-Host "===== RedKite should be used as part of a full investigation =====" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "The checks covered in this version include;"
    Write-Host " -External redirects"
    Write-Host " -Mailbox rules (Delete email, Move to folder and mark as read)"
    Write-Host " -Recent mailbox changes (optional)"
    Write-Host " "
    Write-Host "Please choose from the following options and connect to MgGraph/ExchangeOnline with admin privileges when prompted" -ForegroundColor Yellow
	 Write-Host " "
	
	
    # connect to Exchange Online
    Write-Host "[1/4] Connect to exchange online" -ForegroundColor Cyan
    try {
        # Optional: enforce minimum version
        # $requiredVersion = [Version]"3.3.0"
        # $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Version -ge $requiredVersion }
        # if (-not $exoModule) {
        #     throw "ExchangeOnlineManagement $requiredVersion or newer is required."
        # }

        Connect-ExchangeOnline -ShowProgress:$false -ErrorAction Stop
        Write-Host "Connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        return
    }

    #  Prompt for user selection
    $choice = Read-Host "Would you like to check (A)ll users or (S)pecific users? [A/S]"
    $users = @()

    if ($choice -match '^[Ss]') {
        do {
            $user = Read-Host "Enter mailbox to check or press Enter to finish"
            if ($user) {
                $users += $user
            }
        } while ($user)
    }
    else {
        Write-Host "Option 'Check all users from Azure AD' selected" -ForegroundColor Cyan

        # Connect to Graph only if needed
        Write-Host "[2/4] Connecting to Microsoft Graph..." -ForegroundColor Cyan
        try {
            Connect-Graph -Scopes "User.Read.All" -NoWelcome
            Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
            $users = Get-MgUser -All -Property UserPrincipalName | Select-Object -ExpandProperty UserPrincipalName
        }
        catch {
            Write-Error "Failed to get users from Azure AD: $($_.Exception.Message)"
            return
        }
    }

    # Prompt for log folder
    $defaultFolder = "$HOME\Documents\RedkiteLogs"
    $logFolder = Read-Host "Enter folder path for logs or press Enter to use default [$defaultFolder]"
    if ([string]::IsNullOrWhiteSpace($logFolder)) {
        $logFolder = $defaultFolder
    }
    if (-not (Test-Path $logFolder)) {
        try {
            New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
        }
        catch {
            Write-Error "Failed to create log folder: $($_.Exception.Message)"
            return
        }
    }

    # Set up logging
    $logFile = Join-Path -Path $logFolder -ChildPath "Redkite_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Host "Logs will be saved to $logFile" -ForegroundColor Cyan
    # Prompt for lookback days
    $lookbackDaysInput = Read-Host "Enter how many days back to check (default is 90)"
    if (-not [int]::TryParse($lookbackDaysInput, [ref]$null) -or [int]$lookbackDaysInput -le 0) {
        $lookbackDays = 90
    }
    else {
        $lookbackDays = [int]$lookbackDaysInput
    }
    Write-Host "Lookback period set to $lookbackDays days." -ForegroundColor Cyan

    function Get-M365PhishIndicators {
        param(
            [string[]]$usersChecked,
            [string]$LogFile,
            [int]$LookbackDays
        )

        $results = @()

try {
    # Retrieve accepted domains
    Write-Host "Retrieving accepted domains from Exchange Online..." -ForegroundColor Cyan
    try {
        $acceptedDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
        Write-Host "Detected accepted domains: $($acceptedDomains -join ', ')" -ForegroundColor Green
    }
    catch {
        Write-Warning "Unable to retrieve accepted domains from Exchange Online. Please check your permissions."
        $acceptedDomains = @()
    }
}
catch {
    $errorMsg = "Error connecting to Exchange Online: $($_.Exception.Message)"
    Write-Log $errorMsg $LogFile "ERROR"
    $results += [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Level     = "ERROR"
        Check     = "Exchange Online Connection"
        Detail    = $errorMsg
        Status    = "ERROR"
    }
    return $results
}
# Inbox Rules Check
Write-Host "[2/4] Checking inbox rules (Exchange Online)..." -ForegroundColor Cyan
try {
    $totalUsers = $usersChecked.Count
    for ($i = 0; $i -lt $totalUsers; $i++) {
        $user = $usersChecked[$i]

        # Update progress bar
        $percentComplete = [int](($i / $totalUsers) * 100)
        Write-Progress -Activity "Checking inbox rules" -Status "Processing user $($user) ($($i+1)/$totalUsers)" -PercentComplete $percentComplete

        try {
            $rules = Get-InboxRule -Mailbox $user -ErrorAction Stop
            foreach ($rule in $rules) {
                # Check for suspicious actions
                if (
                    ($rule.DeleteMessage) -or
                    ($rule.MarkAsRead) -or
                    ($rule.MoveToFolder -and $rule.MarkAsRead)
                ) {
                    $entry = [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Level     = "ALERT"
                        Check     = "Inbox Rules"
                        Detail    = "User: $user - Rule: $($rule.Name) - Action: " +
                                    "$(if ($rule.DeleteMessage) {'DeleteMessage '})" +
                                    "$(if ($rule.MarkAsRead) {'MarkAsRead '})" +
                                    "$(if ($rule.MoveToFolder) {'MoveToFolder: ' + $rule.MoveToFolder.FolderPath})"
                        Status    = "Suspicious mailbox rules - Investigation advised"
                    }
                    $results += $entry
                    Write-Log $entry.Detail $LogFile "ALERT"
                }

                # Check for external forwarding in inbox rules
                if ($rule.ForwardTo -and $rule.ForwardTo.Count -gt 0) {
                    foreach ($recipient in $rule.ForwardTo) {
                        $recipientAddress = $recipient.ToString()
                        $recipientDomain = ($recipientAddress -split "@")[-1].ToLower()

                        if (-not ($acceptedDomains -contains $recipientDomain)) {
                            $entry = [PSCustomObject]@{
                                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                Level     = "ALERT"
                                Check     = "Inbox Rules"
                                Detail    = "User: $user - Rule: $($rule.Name) - Action: Forward to external address: $recipientAddress"
                                Status    = "External forward in place"
                            }
                            $results += $entry
                            Write-Log $entry.Detail $LogFile "ALERT"
                        }
                    }
                }
            }
        }
        catch {
            $errorMessage = $_.Exception.Message

            if ($errorMessage -match "(?i)couldn't be found|RecipientNotFound|doesn't exist|does not exist|cannot be found") {
                if ($errorMessage -match "(?i)\balias\b|\bis an alias\b|\balternate address\b|\bmail-enabled contact\b|\bforwarding\b") {
                    $errorMsg = "Mailbox is an alias or forwarding address for user ${user}. Skipping..."
                }
                else {
                    $errorMsg = "Mailbox is an alias or does not exist for user ${user}. Skipping..."
                }
                Write-Log $errorMsg $LogFile "WARN"
            }
            else {
                $errorMsg = "Error checking inbox rules for ${user}: $($_.Exception.Message)"
                Write-Log $errorMsg $LogFile "ERROR"
                $results += [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Level     = "ERROR"
                    Check     = "Inbox Rules"
                    Detail    = $errorMsg
                    Status    = "ERROR"
                }
            }
        }
    }
    # Clear inbox rules progress bar
    Write-Progress -Activity "Checking inbox rules" -Completed
}
catch {
    $errorMsg = "Error during inbox rules check: $($_.Exception.Message)"
    Write-Log $errorMsg $LogFile "ERROR"
    $results += [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Level     = "ERROR"
        Check     = "Inbox Rules"
        Detail    = $errorMsg
        Status    = "ERROR"
    }
}

# --- Now, check Shared Mailboxes separately, AFTER processing all user inbox rules ---
Write-Host "[3/4] Checking shared mailboxes for suspicious settings, please wait..." -ForegroundColor Cyan
try {
    $allSharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
$sharedMailboxes = $allSharedMailboxes | Where-Object { $users -contains $_.UserPrincipalName }

    $totalShared = $sharedMailboxes.Count

    for ($k = 0; $k -lt $totalShared; $k++) {
        $sharedMbx = $sharedMailboxes[$k]

        # Update progress bar
        $percentComplete = [int](($k / $totalShared) * 100)
        Write-Progress -Activity "Checking shared mailboxes..." -Status "Processing shared mailbox $($sharedMbx.UserPrincipalName) ($($k+1)/$totalShared)" -PercentComplete $percentComplete

        try {
            # Check mailbox forwarding settings
            $mbxDetails = Get-Mailbox -Identity $sharedMbx.UserPrincipalName -ErrorAction Stop
            if ($mbxDetails.ForwardingSMTPAddress) {
                $forwardAddress = $mbxDetails.ForwardingSMTPAddress.ToString()
                $forwardDomain = ($forwardAddress -split "@")[-1].ToLower()
                if (-not ($acceptedDomains -contains $forwardDomain)) {
                    $entry = [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Level     = "ALERT"
                        Check     = "Shared Mailboxes"
                        Detail    = "Shared mailbox: $($sharedMbx.UserPrincipalName) forwards mail externally to $forwardAddress"
                        Status    = "External forwarding on shared mailbox"
                    }
                    $results += $entry
                    Write-Log $entry.Detail $LogFile "ALERT"
                }
            }

            # Check inbox rules on shared mailboxes:
            $rules = Get-InboxRule -Mailbox $sharedMbx.UserPrincipalName -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                if (
                    ($rule.DeleteMessage) -or
                    ($rule.MarkAsRead) -or
                    ($rule.MoveToFolder -and $rule.MarkAsRead)
                ) {
                    $entry = [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Level     = "ALERT"
                        Check     = "Shared Mailboxes - Inbox Rules"
                        Detail    = "Shared mailbox: $($sharedMbx.UserPrincipalName) - Rule: $($rule.Name) - Action: " +
                                    "$(if ($rule.DeleteMessage) {'DeleteMessage '})" +
                                    "$(if ($rule.MarkAsRead) {'MarkAsRead '})" +
                                    "$(if ($rule.MoveToFolder) {'MoveToFolder: ' + $rule.MoveToFolder.FolderPath})"
                        Status    = "Suspicious mailbox rules on shared mailbox"
                    }
                    $results += $entry
                    Write-Log $entry.Detail $LogFile "ALERT"
                }
            }
        }
        catch {
            $errorMsg = "Error checking shared mailbox $($sharedMbx.UserPrincipalName): $($_.Exception.Message)"
            Write-Log $errorMsg $LogFile "ERROR"
            $results += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Level     = "ERROR"
                Check     = "Shared Mailboxes"
                Detail    = $errorMsg
                Status    = "ERROR"
            }
        }
    }

             # Clear progress bar
        Write-Progress -Activity "Checking inbox rules" -Completed
        }
        catch {
            $errorMsg = "Error during inbox rules check: $($PSItem.Exception.Message)"
            Write-Log $errorMsg $LogFile "ERROR"
            $results += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Level     = "ERROR"
                Check     = "Inbox Rules"
                Detail    = $errorMsg
                Status    = "ERROR"
            }
        }

 # Prompt user to continue
    Write-Host
    $continue = Read-Host "Do you want to continue with checking for recent 'UpdateInboxRules'/'Set-Mailbox' changes? (Y/N)"
    if ($continue -ne "Y" -and $continue -ne "y") {
        Write-Host "Skipping recent mailbox changes. Outputting inbox rules results only." -ForegroundColor Yellow
        return $results
    }

        # Recent Mailbox Changes
        try {
            Write-Host "[4/4] Checking recent mailbox changes (Exchange Online)..." -ForegroundColor Cyan
           $mailboxes = @()
foreach ($user in $users) {
    try {
        $mailbox = Get-Mailbox -Identity $user -ErrorAction Stop
        $mailboxes += $mailbox
    }
    catch {
       Write-Log "Could not retrieve mailbox for ${user}: $($_.Exception.Message)" $LogFile "WARN"
    }
}
            
             $totalMailboxes = $mailboxes.Count
        for ($j = 0; $j -lt $totalMailboxes; $j++) {
            $mbx = $mailboxes[$j]

            # Update progress bar
            $percentComplete = [int](($j / $totalMailboxes) * 100)
            Write-Progress -Activity "Checking recent mailbox changes" -Status "Processing mailbox $($mbx.UserPrincipalName) ($($j+1)/$totalMailboxes)" -PercentComplete $percentComplete
            
                try {
                    $auditLogs = Search-MailboxAuditLog -Identity $mbx.UserPrincipalName `
                        -LogonTypes Owner,Delegate,Admin -ShowDetails `
                        -StartDate (Get-Date).AddDays(-$LookbackDays) `
                        -ErrorAction Stop
                    foreach ($log in $auditLogs) {
                        if ($log.Operation -eq "UpdateInboxRules" -or $log.Operation -eq "Set-Mailbox") {
                            $results += [PSCustomObject]@{
                                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                Level     = "ALERT"
                                Check     = "Recent Mailbox Changes"
                                Detail    = "User: $($mbx.UserPrincipalName) - Action: $($log.Operation)"
                                Status    = "ALERT"
                            }
                            Write-Log "Recent Mailbox Change detected: User: $($mbx.UserPrincipalName) - Action: $($log.Operation)" $LogFile "ALERT"
                        }
                    }
                }
                catch {
    if ($errorMessage -match "(?i)couldn't be found|RecipientNotFound|doesn't exist|does not exist|cannot be found") {
        if ($errorMessage -match "(?i)\balias\b|\bis an alias\b|\balternate address\b|\bmail-enabled contact\b|\bforwarding\b") {
            $errorMsg = "Mailbox is an alias or forwarding address for user ${user}. Skipping..."
        }
        else {
            $errorMsg = "Mailbox is an alias or does not exist for user ${user}. Skipping..."
        }
        Write-Log $errorMsg $LogFile "WARN"
    }
                        $errorMsg = "Error retrieving mailbox changes for user $($mbx.UserPrincipalName): $($_.Exception.Message)"
                        Write-Log $errorMsg $LogFile "ERROR"
                        $results += [PSCustomObject]@{
                            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Level     = "ERROR"
                            Check     = "Recent Mailbox Changes"
                            Detail    = $errorMsg
                            Status    = "ERROR"
                        }
                    }
                }
            
            # Clear progress bar
        Write-Progress -Activity "Checking recent mailbox changes" -Completed
        }
        catch {
            $results += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Level     = "ERROR"
                Check     = "Recent Mailbox Changes"
                Detail    = "Error: $_"
                Status    = "ERROR"
            }
        }

        # Summary entry if no alerts are found at all across any mailboxes
if (-not ($results | Where-Object { $_.Status -eq "ALERT" })) {
    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Level     = "INFO"
        Check     = "Summary"
        Detail    = "RedKite checks complete."
        Status    = "OK"
    }
    $results += $entry
    Write-Log $entry.Detail $LogFile "INFO"
}

return $results
    }



    # Run main checks
    $results = Get-M365PhishIndicators -usersChecked $users -LogFile $logFile -LookbackDays $lookbackDays

    Write-Host "Redkite checks completed." -ForegroundColor Cyan

    # Export results option
    $exportChoice = Read-Host "Would you like to export the results to a CSV file? (Y/N)"
    if ($exportChoice -match '^[Yy]') {
        $defaultExportFolder = "$HOME\Documents\RedkiteResults"
        $exportFolder = Read-Host "Enter folder path to save CSV or press Enter to use default [$defaultExportFolder]"
        if ([string]::IsNullOrWhiteSpace($exportFolder)) {
            $exportFolder = $defaultExportFolder
        }
        if (-not (Test-Path $exportFolder)) {
            try {
                New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
            }
            catch {
                Write-Error "Failed to create export folder: $($_.Exception.Message)"
                return
            }
        }
        $csvFile = Join-Path -Path $exportFolder -ChildPath "Redkite_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $results | Export-Csv -Path $csvFile -NoTypeInformation -Force
            Write-Host "Results exported to $csvFile"
        }
        catch {
            Write-Error "Failed to export CSV: $($_.Exception.Message)"
        }
    }
     # Prompt to disconnect
    Write-Host
    $disconnect = Read-Host "Do you want to disconnect from Exchange Online and Microsoft Graph? (Y/N)"
    if ($disconnect -eq "Y" -or $disconnect -eq "y") {
        try {
            Write-Host "Disconnecting from Exchange Online..." -ForegroundColor Cyan
            Disconnect-ExchangeOnline -Confirm:$false

            Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Cyan
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Error disconnecting: $($_.Exception.Message)"
        }
    }
 }
 
Export-ModuleMember -Function Write-Log, Test-RequiredModules, Start-Redkite, Clear-GraphTokenCache, Get-M365PhishIndicators




# SIG # Begin signature block
# MIIFVQYJKoZIhvcNAQcCoIIFRjCCBUICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUU2K6NCah3ldafs0JToJkjAs6
# b9OgggL4MIIC9DCCAdygAwIBAgIQY+vPo58WzL1B8Von0QzZrjANBgkqhkiG9w0B
# AQsFADASMRAwDgYDVQQDDAdSZWRLaXRlMB4XDTI1MDYwMzE4NDg0NloXDTI2MDYw
# MzE5MDg0NlowEjEQMA4GA1UEAwwHUmVkS2l0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALFokoxPL60YLnNP3LuIM9j+XEux+RMhis2LmfgiTsM7XixC
# brR3plmrNNcDrBZv5GySvcdUhz+/1ARaUQgJWZwntG5jpDG1DMk67nCLjtaXhmhJ
# kQzVUSplEa6yjutCMYqGjLyt8tpwq6dqgEdskDYzURm8Z/7gxnnw1qHAuKSwOH9z
# bfMJgatlktkBMd+YwKGhOHjF3qQaVf6VGUXOrMUP+97XjfmeYOkqewU3IZ2cLqxk
# jwGdAJ9td14DZl45kqVqupMwa9jaC25LzoVp9vXQGkiOQs12pPT5uWtRO2K/x2GD
# IQL0dEMwJXFJM3QOrjQp+gWGtadFBVvuIEaG910CAwEAAaNGMEQwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRK3QorQIBVPxl2
# E5NSs/r5zZHq7jANBgkqhkiG9w0BAQsFAAOCAQEAhxAp9FWqs5UYKmDAh0Blob3T
# Ug3dYRjaLJuX9o9XglSNYCTHVkRKjVTmChVzc4cYw9Vqytw9wP1ZO/xTiRg7eGtY
# 05rrfkxxE++9+Y+0NOCBuiPrJ3UKME+gb6tCSmakjK5Q/f3DJ8RuLyETCi1EL/ui
# GrEZltVkcTl4ENYYdBVCKMC3RWQL/RdEXVDxzM/qb2gdUHEwMHOtLEqrJELcFqgZ
# h0EjbYYrcq61u1tYiNWvyHieEHmJpgDfIxkAhWrEDYSviyyu+UGUvmsgM8BoafCK
# 99iSNGPN9QibQRNtZwCAXfBqBzFr/enT/JiP8puy3E4ZHTAx6+6/t1FOoxF5aDGC
# AccwggHDAgEBMCYwEjEQMA4GA1UEAwwHUmVkS2l0ZQIQY+vPo58WzL1B8Von0QzZ
# rjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAjBgkqhkiG9w0BCQQxFgQUYMjfzcvAuTXOZ/AepKqmlf9F/okwDQYJKoZIhvcN
# AQEBBQAEggEAHpsXET8VcZ1hyzyNLq3ivJhUm6KuCASu8fXf8uQybVsESE5Ocnu3
# TdECFwWms4tX7AmSOm9zTgJwZTVPnyPIA1an2U9KcWyTnvlE7GpvZYzjJ/+ltdLs
# 7NLnEE7FS8NnlVQ7TdonO9WikDj+4E2At1LVuUb5sLji5fzy5nJf7seLcykQkK3q
# 0abT517cZuVDp6xLITHhx/4/D/f1aED4646AFLEz9IIbKePh7onsgDd0j3Jg+1tp
# wX3QeEKyGFSJtUm1gc3v/7aPw6+gVkxJMXXXxyREcIp9Ku5UP3MnoFrDvzbq5NL5
# 8IXwurlF6iWzMCR2ziyKHvh0Wi+C/4mwaw==
# SIG # End signature block
