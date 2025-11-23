# Automated Setup Scripts

This folder includes automated setup scripts to streamline the Azure AD configuration process for the MSAuth 1.0 demonstration application.

## Available Scripts

### setup-azure.ps1 (Windows PowerShell)

Automates Azure AD setup on Windows using PowerShell.

**Usage:**

```powershell
# Basic usage with defaults
.\setup-azure.ps1

# Custom app name
.\setup-azure.ps1 -AppName "MyMSAuth10App"

# Custom certificate name
.\setup-azure.ps1 -CertificateName "MyMSAuth10Cert"

# Skip certificate creation (use existing certificate)
.\setup-azure.ps1 -SkipCertificateCreation
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-AppName` | Name of the Azure AD app registration | `MSAuth10-PocApp` |
| `-CertificateName` | Name for the generated certificate | `MSAuth10PocApp` |
| `-SkipCertificateCreation` | Skip certificate generation | `$false` |

### setup-azure.sh (Linux/macOS Bash)

Automates Azure AD setup on Linux and macOS using Bash.

**Usage:**

```bash
# Basic usage with defaults
./setup-azure.sh

# Custom app name
./setup-azure.sh "MyMSAuth10App"

# Custom app and certificate names
./setup-azure.sh "MyMSAuth10App" "MyMSAuth10Cert"

# Skip certificate creation
SKIP_CERT=true ./setup-azure.sh
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `$1` | Name of the Azure AD app registration | `MSAuth10-PocApp` |
| `$2` | Name for the generated certificate | `MSAuth10PocApp` |
| `SKIP_CERT` | Environment variable to skip certificate generation | `false` |

## What the Scripts Do

Both scripts perform the following operations:

1. **Prerequisites Check**
   - Verifies Azure CLI is installed and available
   - Checks for OpenSSL (Linux/macOS) or PowerShell cmdlets (Windows)

2. **Azure Login**
   - Initiates browser-based Azure CLI login
   - Displays tenant information

3. **Certificate Generation** (unless skipped)
   - Creates a 2048-bit RSA self-signed certificate
   - Valid for 2 years from creation
   - Exports public key (.cer/.crt) and private key (.key/.pfx)
   - Displays certificate thumbprint

4. **App Registration**
   - Creates or reuses Azure AD app registration
   - Configures as single-tenant application
   - Retrieves application (client) ID

5. **API Permissions**
   - Adds Microsoft Graph API permissions:
     - `User.Read.All` (Application permission)
   - Attempts to grant admin consent automatically

6. **Certificate Upload**
   - Uploads the generated certificate to the app registration
   - Associates the public key with the application

7. **Configuration Update**
   - Updates `MSAuth10PocApp/appsettings.json` with:
     - Tenant ID
     - Client ID
     - Certificate thumbprint (if generated)

8. **Summary**
   - Displays configuration values
   - Provides Azure Portal link for verification
   - Shows next steps

## Prerequisites

### Both Scripts

- **Azure CLI** - Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
  - Verify: `az --version`
- **Azure AD tenant** with admin access
- **Admin permissions** to:
  - Create app registrations
  - Grant admin consent for API permissions
  - Upload certificates

### Windows (PowerShell)

- PowerShell 5.1 or later (included with Windows 10/11)
- Windows certificate store access

### Linux/macOS (Bash)

- Bash shell
- OpenSSL - Usually pre-installed
  - macOS: `brew install openssl`
  - Linux: Typically included
- `jq` - For JSON manipulation (optional but recommended)
  - macOS: `brew install jq`
  - Linux: `sudo apt-get install jq` or `sudo yum install jq`

## Output Files

After running the scripts, you'll find:

### Windows (PowerShell)

```
msauth1.0_poc/
├── MSAuth10PocApp.cer          # Public certificate (for Azure AD)
└── MSAuth10PocApp/
    └── appsettings.json        # Updated with your configuration
```

The certificate is installed in: `Cert:\CurrentUser\My\{thumbprint}`

### Linux/macOS (Bash)

```
msauth1.0_poc/
├── MSAuth10PocApp.crt          # Public certificate
├── MSAuth10PocApp.key          # Private key
├── MSAuth10PocApp.pfx          # PKCS#12 bundle (for Windows compatibility)
└── MSAuth10PocApp/
    └── appsettings.json        # Updated with your configuration
```

## Troubleshooting

### Azure CLI Not Found

**Error:**
```
❌ Azure CLI is not installed.
```

**Solution:**
Install Azure CLI from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

Verify installation:
```bash
az --version
```

### Login Failed

**Error:**
```
❌ Failed to login to Azure
```

**Solutions:**
1. Ensure you have an active Azure account
2. Check your internet connection
3. Try logging in manually: `az login`
4. Clear Azure CLI cache: `az account clear`

### Admin Consent Failed

**Warning:**
```
⚠️  Warning: Could not grant admin consent automatically
```

**Solution:**
Grant consent manually in Azure Portal:
1. Go to Azure AD > App registrations
2. Select your application
3. Go to API permissions
4. Click "Grant admin consent for [Your Tenant]"

### Certificate Upload Failed

**Warning:**
```
⚠️  Warning: Could not upload certificate automatically
```

**Solution:**
Upload certificate manually in Azure Portal:
1. Go to Azure AD > App registrations
2. Select your application
3. Go to Certificates & secrets
4. Upload the `.cer` (Windows) or `.crt` (Linux/macOS) file

### Configuration Update Failed

**Warning:**
```
⚠️  Warning: Could not update appsettings.json automatically
```

**Solution:**
Manually update `MSAuth10PocApp/appsettings.json`:
```json
{
  "AzureAd": {
    "TenantId": "YOUR_TENANT_ID",
    "ClientId": "YOUR_CLIENT_ID",
    "CertificateThumbprint": "YOUR_CERT_THUMBPRINT"
  }
}
```

## Security Notes

### Certificate Storage

**Windows:**
- Certificates are stored in the Windows Certificate Store
- Use `certmgr.msc` to view/manage certificates
- Private keys are marked as exportable

**Linux/macOS:**
- Certificate and private key files are created in the script directory
- **Important:** Protect the `.key` and `.pfx` files - they contain your private key
- Consider using file permissions: `chmod 600 MSAuth10PocApp.key`

### Cleaning Up

To remove the app registration after testing:

```bash
# Get the app ID
az ad app list --display-name "MSAuth10-PocApp" --query "[0].appId" -o tsv

# Delete the app registration
az ad app delete --id <APP_ID>
```

To remove certificates:

**Windows:**
```powershell
# Find certificate by subject
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=MSAuth10PocApp"}

# Remove certificate
Remove-Item Cert:\CurrentUser\My\{THUMBPRINT}
```

**Linux/macOS:**
```bash
rm MSAuth10PocApp.crt MSAuth10PocApp.key MSAuth10PocApp.pfx
```

## Advanced Usage

### Using with Existing Certificates

If you already have a certificate:

**Windows:**
```powershell
.\setup-azure.ps1 -SkipCertificateCreation
# Then manually update appsettings.json with your certificate thumbprint
```

**Linux/macOS:**
```bash
SKIP_CERT=true ./setup-azure.sh
# Then manually update appsettings.json with your certificate thumbprint
```

### Using with Different Azure Cloud

The scripts default to Azure Public Cloud. For other clouds, you may need to modify the scripts or use az login parameters:

```bash
# Azure Government
az login --allow-no-subscriptions --cloud AzureUSGovernment

# Azure China
az login --allow-no-subscriptions --cloud AzureChinaCloud
```

## Support

For issues with the setup scripts:
- Review the troubleshooting section above
- Check script output for specific error messages
- Verify all prerequisites are met
- Refer to [TEST_SETUP_GUIDE.md](TEST_SETUP_GUIDE.md) for manual setup instructions

For general MSAuth 1.0 questions:
- See [README.md](README.md) for quick start
- See [TEST_SETUP_GUIDE.md](TEST_SETUP_GUIDE.md) for comprehensive documentation
