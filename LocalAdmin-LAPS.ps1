# Define the path for local log file
$logFilePath = "C:\Path\To\Your\Log\EnableLocalAdminLog.txt"

# LogMessage function to write logs to both a text file and the Application Event Log
function LogMessage {
    param(
        [string]$message
    )
    
    # Get current timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Write log to text file
    Add-Content -Path $logFilePath -Value "$timestamp - $message"
    
    # Write log to Application Event Log
    Write-EventLog -LogName Application -Source "EnableLocalAdminScript" -EventId 1001 -EntryType Information -Message $message

    # Send logs to Log Analytics
    $workspaceId = "YourLogAnalyticsWorkspaceId"
    $workspaceKey = "YourLogAnalyticsWorkspaceKey"
    $logData = @{
        "Timestamp" = $timestamp
        "Message" = $message
    }
    $jsonLog = $logData | ConvertTo-Json
    $headers = @{
        "Content-Type" = "application/json"
        "Log-Type" = "EnableLocalAdminLog"
        "Authorization" = "SharedKeyLite $workspaceId:$workspaceKey"
    }
    $uri = "https://$workspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonLog
}

# Azure Key Vault details
$keyVaultName = "YourKeyVaultName"
$secretName = "LocalAdminPassword"

# Retrieve secret from Azure Key Vault
$secret = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName).SecretValueText

# Local Admin Account details
$userName = "Administrator"
$computer = $env:COMPUTERNAME

# Check if account already exists
$existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

if ($existingUser -eq $null) {
    # Create new local user
    $securePassword = ConvertTo-SecureString -String $secret -AsPlainText -Force
    New-LocalUser -Name $userName -Password $securePassword -Description "Local Admin Account" -UserMayNotChangePassword

    # Set password to be managed by LAPS
    Set-AdmPwdAccountPassword -Identity $userName

    # Add user to local administrators group
    Add-LocalGroupMember -Group "Administrators" -Member $userName

    # Log creation and addition to Administrators group
    LogMessage "Local Admin account '$userName' created, managed by LAPS, and added to Administrators group on computer '$computer'."
} else {
    # Check if user is already a member of the Administrators grou
