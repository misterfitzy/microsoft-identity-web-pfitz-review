# MSAuth 1.0 POC - Azure AD Setup Script (PowerShell)
# This script automates the Azure AD configuration for the MSAuth 1.0 demonstration application

param(
    [Parameter(Mandatory=$false)]
    [string]$AppName = "MSAuth10-PocApp",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificateName = "MSAuth10PocApp",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipCertificateCreation
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "MSAuth 1.0 POC - Azure AD Setup Script" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Azure CLI is installed
Write-Host "[Step 1/8] Checking prerequisites..." -ForegroundColor Yellow
try {
    $azVersion = az --version 2>&1 | Select-String "azure-cli" | Select-Object -First 1
    Write-Host "✓ Azure CLI is installed: $azVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Azure CLI is not installed." -ForegroundColor Red
    Write-Host "Please install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" -ForegroundColor Yellow
    exit 1
}

# Check Azure login status
Write-Host ""
Write-Host "[Step 2/8] Checking Azure login status..." -ForegroundColor Yellow

# Try to get account info to check if already logged in
$accountCheckResult = az account show 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Already logged in to Azure" -ForegroundColor Green
    $account = $accountCheckResult | ConvertFrom-Json
} else {
    Write-Host "Not currently logged in. A browser window will open for authentication." -ForegroundColor Gray
    $loginResult = az login --allow-no-subscriptions 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to login to Azure" -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Successfully logged in to Azure" -ForegroundColor Green
    # Get account info after successful login
    $accountCheckResult = az account show 2>&1
    $account = $accountCheckResult | ConvertFrom-Json
}

# Get tenant information
$tenantId = $account.homeTenantId
$tenantName = $account.name

Write-Host "  Tenant ID: $tenantId" -ForegroundColor Gray
Write-Host "  Tenant Name: $tenantName" -ForegroundColor Gray

# Create certificate if not skipped
$certThumbprint = ""
if (-not $SkipCertificateCreation) {
    Write-Host ""
    Write-Host "[Step 3/8] Creating self-signed certificate..." -ForegroundColor Yellow
    
    try {
        $cert = New-SelfSignedCertificate `
            -Subject "CN=$CertificateName" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable `
            -KeySpec Signature `
            -KeyLength 2048 `
            -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(2)
        
        $certThumbprint = $cert.Thumbprint
        Write-Host "✓ Certificate created successfully" -ForegroundColor Green
        Write-Host "  Thumbprint: $certThumbprint" -ForegroundColor Gray
        
        # Export public key
        $certPath = Join-Path $PSScriptRoot "$CertificateName.cer"
        Export-Certificate -Cert $cert -FilePath $certPath | Out-Null
        Write-Host "  Exported to: $certPath" -ForegroundColor Gray
    } catch {
        Write-Host "❌ Failed to create certificate: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[Step 3/8] Skipping certificate creation (--SkipCertificateCreation)" -ForegroundColor Yellow
    Write-Host "⚠️  You will need to manually specify a certificate thumbprint" -ForegroundColor Yellow
}

# Create app registration
Write-Host ""
Write-Host "[Step 4/8] Creating app registration..." -ForegroundColor Yellow

$appExists = az ad app list --display-name $AppName | ConvertFrom-Json
if ($appExists.Count -gt 0) {
    Write-Host "⚠️  App '$AppName' already exists" -ForegroundColor Yellow
    $app = $appExists[0]
    $appId = $app.appId
} else {
    $appJson = az ad app create --display-name $AppName --sign-in-audience "AzureADMyOrg" | ConvertFrom-Json
    $appId = $appJson.appId
    Write-Host "✓ App registration created" -ForegroundColor Green
}

Write-Host "  Application (Client) ID: $appId" -ForegroundColor Gray

# Get the app object ID for further operations
$appObjectId = (az ad app show --id $appId | ConvertFrom-Json).id

# Configure API permissions
Write-Host ""
Write-Host "[Step 5/8] Configuring API permissions..." -ForegroundColor Yellow

# Microsoft Graph API ID
$graphApiId = "00000003-0000-0000-c000-000000000000"

# User.Read.All permission ID
$userReadAllId = "df021288-bdef-4463-88db-98f22de89214"

try {
    # Add the permission
    az ad app permission add --id $appId --api $graphApiId --api-permissions "$userReadAllId=Role" | Out-Null
    Write-Host "✓ Added Microsoft Graph User.Read.All permission" -ForegroundColor Green
    
    # Grant admin consent
    Write-Host "  Granting admin consent..." -ForegroundColor Gray
    Start-Sleep -Seconds 5  # Wait for permission to propagate
    
    az ad app permission grant --id $appId --api $graphApiId --scope "User.Read.All" | Out-Null
    az ad app permission admin-consent --id $appId | Out-Null
    
    Write-Host "✓ Admin consent granted" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Warning: Could not grant admin consent automatically" -ForegroundColor Yellow
    Write-Host "  You may need to grant consent manually in Azure Portal" -ForegroundColor Gray
}

# Upload certificate if created
if (-not $SkipCertificateCreation) {
    Write-Host ""
    Write-Host "[Step 6/8] Uploading certificate to app registration..." -ForegroundColor Yellow
    
    try {
        $certPath = Join-Path $PSScriptRoot "$CertificateName.cer"
        az ad app credential reset --id $appId --cert "@$certPath" --append | Out-Null
        Write-Host "✓ Certificate uploaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Warning: Could not upload certificate automatically" -ForegroundColor Yellow
        Write-Host "  You may need to upload it manually in Azure Portal" -ForegroundColor Gray
    }
} else {
    Write-Host ""
    Write-Host "[Step 6/8] Skipping certificate upload" -ForegroundColor Yellow
}

# Update appsettings.json
Write-Host ""
Write-Host "[Step 7/8] Updating appsettings.json..." -ForegroundColor Yellow

$appSettingsPath = Join-Path $PSScriptRoot "MSAuth10PocApp\appsettings.json"

if (Test-Path $appSettingsPath) {
    try {
        $appSettings = Get-Content $appSettingsPath -Raw | ConvertFrom-Json
        
        $appSettings.AzureAd.TenantId = $tenantId
        $appSettings.AzureAd.ClientId = $appId
        
        if (-not $SkipCertificateCreation) {
            $appSettings.AzureAd.CertificateThumbprint = $certThumbprint
        }
        
        $appSettings | ConvertTo-Json -Depth 10 | Set-Content $appSettingsPath
        Write-Host "✓ Configuration updated successfully" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Warning: Could not update appsettings.json automatically" -ForegroundColor Yellow
        Write-Host "  Please update manually with the values shown below" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠️  appsettings.json not found at: $appSettingsPath" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "[Step 8/8] Setup Complete!" -ForegroundColor Yellow
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Configuration Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Tenant ID:              $tenantId" -ForegroundColor White
Write-Host "Application Client ID:  $appId" -ForegroundColor White

if (-not $SkipCertificateCreation) {
    Write-Host "Certificate Thumbprint: $certThumbprint" -ForegroundColor White
    Write-Host "Certificate Location:   Cert:\CurrentUser\My\$certThumbprint" -ForegroundColor White
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Green
Write-Host "1. Verify the configuration in Azure Portal:" -ForegroundColor Gray
Write-Host "   https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$appId" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Run the demonstration app:" -ForegroundColor Gray
Write-Host "   cd MSAuth10PocApp" -ForegroundColor Gray
Write-Host "   dotnet run" -ForegroundColor Gray
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
