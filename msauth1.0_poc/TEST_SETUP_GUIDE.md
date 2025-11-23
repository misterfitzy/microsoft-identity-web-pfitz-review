# MSAuth 1.0 AT-POP Test Setup Guide

This guide provides complete instructions for setting up and running the MSAuth 1.0 AT-POP (Access Token Proof-of-Possession) demonstration application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Automated Setup (Recommended)](#automated-setup-recommended)
4. [Manual Azure AD Setup](#manual-azure-ad-setup)
5. [Certificate Setup](#certificate-setup)
6. [Application Configuration](#application-configuration)
7. [Running the Application](#running-the-application)
8. [Understanding the Output](#understanding-the-output)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)

---

## Overview

### What is MSAuth 1.0 AT-POP?

MSAuth 1.0 AT-POP is a security enhancement for OAuth 2.0 that protects against token theft and replay attacks by:

- **Cryptographically binding** access tokens to a client-generated key pair
- **Requiring proof of possession** of the private key when using the token
- **Preventing token theft** - stolen tokens are useless without the private key

### What This Demo Shows

This application demonstrates:

1. Generating an RSA key pair for Proof-of-Possession
2. Acquiring a PoP token from Azure AD using MSAuth 1.0 protocol
3. Inspecting the token to verify the cryptographic binding
4. Using the PoP token to call Microsoft Graph API

---

## Prerequisites

### Software Requirements

- **.NET 8.0 SDK or later**
  - Download from: https://dotnet.microsoft.com/download/dotnet/8.0
  - Verify installation: `dotnet --version`

- **Azure CLI** (for automated setup)
  - Download from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
  - Verify installation: `az --version`

- **PowerShell** (for certificate generation on Windows)
  - Windows: Built-in
  - macOS/Linux: Install PowerShell Core from https://github.com/PowerShell/PowerShell

- **OpenSSL** (alternative for certificate generation)
  - Windows: Download from https://slproweb.com/products/Win32OpenSSL.html
  - macOS: `brew install openssl`
  - Linux: Usually pre-installed

### Azure Requirements

- **Azure Active Directory (Entra ID) tenant**
  - You need admin access to register applications
  - Can use a free Azure account: https://azure.microsoft.com/free/

- **Azure AD Admin permissions** for:
  - Registering applications
  - Granting admin consent for API permissions
  - Uploading certificates

---

## Automated Setup (Recommended)

The fastest way to get started is using our automated setup scripts. These scripts will handle all Azure AD configuration automatically.

### Windows (PowerShell)

```powershell
# Navigate to the msauth1.0_poc folder
cd msauth1.0_poc

# Run the setup script
.\setup-azure.ps1

# Optional: Specify custom app name
.\setup-azure.ps1 -AppName "MyCustomApp"

# Optional: Skip certificate creation if you have your own
.\setup-azure.ps1 -SkipCertificateCreation
```

### Linux/macOS (Bash)

```bash
# Navigate to the msauth1.0_poc folder
cd msauth1.0_poc

# Run the setup script
./setup-azure.sh

# Optional: Specify custom app name and certificate name
./setup-azure.sh "MyCustomApp" "MyCertificate"

# Optional: Skip certificate creation
SKIP_CERT=true ./setup-azure.sh
```

### What the Automated Setup Does

The setup script performs the following steps:

1. **✓ Checks prerequisites** - Verifies Azure CLI is installed
2. **✓ Logs in to Azure** - Opens browser for authentication
3. **✓ Creates certificate** - Generates self-signed certificate (2048-bit RSA)
4. **✓ Creates app registration** - Registers application in Azure AD
5. **✓ Configures permissions** - Adds Microsoft Graph User.Read.All permission
6. **✓ Grants admin consent** - Automatically grants consent (if you have permissions)
7. **✓ Uploads certificate** - Adds certificate to app registration
8. **✓ Updates configuration** - Automatically updates appsettings.json

### After Automated Setup

Once the script completes, you'll see a summary with:
- Tenant ID
- Application (Client) ID
- Certificate Thumbprint
- Links to verify in Azure Portal

Simply run the application:

```bash
cd MSAuth10PocApp
dotnet run
```

---

## Manual Azure AD Setup

### Step 1: Register the Application

1. Sign in to the **Azure Portal**: https://portal.azure.com

2. Navigate to **Azure Active Directory** (or **Microsoft Entra ID**)

3. Select **App registrations** from the left menu

4. Click **+ New registration**

5. Configure the application:
   - **Name**: `MSAuth10-PocApp` (or any name you prefer)
   - **Supported account types**: Select **Accounts in this organizational directory only (Single tenant)**
   - **Redirect URI**: Leave empty (not needed for confidential client)

6. Click **Register**

7. **Save the following values** (you'll need them for configuration):
   - **Application (client) ID**: Found on the Overview page (e.g., `12345678-1234-1234-1234-123456789abc`)
   - **Directory (tenant) ID**: Found on the Overview page (e.g., `87654321-4321-4321-4321-cba987654321`)

### Step 2: Configure API Permissions

1. In your app registration, select **API permissions** from the left menu

2. Click **+ Add a permission**

3. Select **Microsoft Graph**

4. Select **Application permissions** (not Delegated)

5. Search for and select the following permissions:
   - `User.Read.All` - Read all users' full profiles
   
   > **Note**: You can add more permissions based on what you want to test. Common options:
   > - `Directory.Read.All` - Read directory data
   > - `Mail.Read` - Read mail in all mailboxes
   > - `Calendars.Read` - Read calendars in all mailboxes

6. Click **Add permissions**

7. **IMPORTANT**: Click **Grant admin consent for [Your Tenant Name]**
   - This requires Global Administrator or Application Administrator role
   - The status should change to green checkmarks

### Step 3: Upload Certificate

You'll create the certificate in the next section, but here's where you'll upload it:

1. In your app registration, select **Certificates & secrets** from the left menu

2. Select the **Certificates** tab

3. Click **Upload certificate**

4. Upload your `.cer` or `.crt` file (public key only)

5. Add a description (e.g., "MSAuth10 PoC Certificate")

6. Click **Add**

7. **Save the thumbprint** value (you'll need it for configuration)

---

## Certificate Setup

You need a certificate for the confidential client application to authenticate with Azure AD. Choose one of the following methods:

### Option 1: Self-Signed Certificate (Recommended for Testing)

#### Windows (PowerShell)

```powershell
# Generate a self-signed certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=MSAuth10PocApp" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Display the thumbprint
Write-Host "Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Export the public key (.cer file) for Azure AD
$certPath = ".\MSAuth10PocApp.cer"
Export-Certificate -Cert $cert -FilePath $certPath
Write-Host "Public certificate exported to: $certPath" -ForegroundColor Green
Write-Host "Upload this .cer file to Azure AD" -ForegroundColor Yellow
```

The certificate is now in your user certificate store and ready to use!

#### macOS/Linux (OpenSSL)

```bash
# Generate private key
openssl genrsa -out MSAuth10PocApp.key 2048

# Generate certificate signing request
openssl req -new -key MSAuth10PocApp.key -out MSAuth10PocApp.csr -subj "/CN=MSAuth10PocApp"

# Generate self-signed certificate
openssl x509 -req -days 730 -in MSAuth10PocApp.csr -signkey MSAuth10PocApp.key -out MSAuth10PocApp.crt

# Create PFX file (needed for importing)
openssl pkcs12 -export -out MSAuth10PocApp.pfx -inkey MSAuth10PocApp.key -in MSAuth10PocApp.crt

# Display thumbprint
openssl x509 -in MSAuth10PocApp.crt -noout -fingerprint -sha1 | sed 's/://g'
```

Then import the PFX file into your certificate store.

### Option 2: Using Existing Certificate

If you already have a certificate:

1. Ensure it's installed in your certificate store:
   - Windows: User or Machine certificate store
   - macOS: Keychain Access
   - Linux: System certificate store

2. Get the thumbprint:
   ```powershell
   # Windows PowerShell
   Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*YourCertName*"}
   ```

3. Export the public key (.cer) to upload to Azure AD

---

## Application Configuration

### Step 1: Update appsettings.json

Navigate to the `msauth1.0_poc/MSAuth10PocApp` directory and edit `appsettings.json`:

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "YOUR_TENANT_ID_HERE",          // From Azure AD Overview
    "ClientId": "YOUR_CLIENT_ID_HERE",          // From Azure AD Overview
    "CertificateThumbprint": "YOUR_CERT_THUMBPRINT_HERE",  // From certificate
    "CertificateStorePath": "CurrentUser/My"    // Certificate store location
  },
  "TargetApi": {
    "BaseUrl": "https://graph.microsoft.com/v1.0",
    "Scopes": [ "https://graph.microsoft.com/.default" ],
    "TestEndpoint": "/users?$top=1"             // Adjust as needed
  }
}
```

### Configuration Values Explained

| Setting | Description | Example |
|---------|-------------|---------|
| `TenantId` | Your Azure AD tenant ID (from app registration) | `87654321-4321-4321-4321-cba987654321` |
| `ClientId` | Your application (client) ID (from app registration) | `12345678-1234-1234-1234-123456789abc` |
| `CertificateThumbprint` | Certificate thumbprint (no spaces, no colons) | `A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2` |
| `CertificateStorePath` | Where the certificate is installed | `CurrentUser/My` or `LocalMachine/My` |

### Certificate Store Path Options

- **Windows**:
  - `CurrentUser/My` - Current user's personal certificate store (most common)
  - `LocalMachine/My` - Local machine's personal certificate store (requires admin)

- **macOS/Linux**:
  - Certificate loading may differ; you might need to use PFX files directly

---

## Running the Application

### Step 1: Build the Application

```bash
cd msauth1.0_poc/MSAuth10PocApp
dotnet build
```

Expected output:
```
Build succeeded.
```

### Step 2: Run the Application

```bash
dotnet run
```

### Step 3: Observe the Output

The application will execute the following steps:

1. ✓ Validate configuration
2. ✓ Generate PoP key pair (RSA 2048-bit)
3. ✓ Acquire MSAuth 1.0 PoP token from Azure AD
4. ✓ Inspect the token to verify PoP binding
5. ✓ Call Microsoft Graph API with the PoP token

---

## Understanding the Output

### Successful Execution

```
===========================================
MSAuth 1.0 AT-POP Demonstration Application
===========================================

✓ Configuration validated
  Tenant ID: 87654321-4321-4321-4321-cba987654321
  Client ID: 12345678-1234-1234-1234-123456789abc
  Certificate Thumbprint: A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2

[Step 1] Generating PoP key pair...
✓ Generated RSA key pair (KeyID: abc-123-def-456)
Public Key (JWK): {"kty":"RSA","n":"...","e":"AQAB","kid":"abc-123-def-456","use":"sig"}

[Step 2] Acquiring MSAuth 1.0 PoP token...
✓ Loaded certificate: CN=MSAuth10PocApp
✓ Successfully acquired PoP token
  Token Type: pop
  Expires On: 11/23/2025 1:30:00 PM
  Scopes: https://graph.microsoft.com/.default

[Step 3] Inspecting PoP access token...
Access Token Claims:
  Issuer: https://login.microsoftonline.com/.../v2.0
  Audiences: https://graph.microsoft.com
  Valid From: 11/23/2025 12:30:00 PM
  Valid To: 11/23/2025 1:30:00 PM
  ✓ Confirmation (cnf) claim found: {"jwk":{"kty":"RSA",...}}
    This proves the token is bound to the PoP key!

[Step 4] Making API call with PoP token...
Calling API: https://graph.microsoft.com/v1.0/users?$top=1
Response Status: 200 OK
✓ API call successful!

Response Preview:
{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users",...}

===========================================
✓ MSAuth 1.0 demonstration completed successfully!
===========================================
```

### Key Indicators of Success

1. **Token Type**: Should be `pop`, not `Bearer`
2. **Confirmation (cnf) claim**: Must be present in the access token
   - This proves the token is cryptographically bound to the PoP key
3. **API Response**: Should be `200 OK` with valid JSON data

---

## Troubleshooting

### Problem: "Certificate not found with thumbprint"

**Symptoms:**
```
Certificate not found with thumbprint: A1B2C3D4...
```

**Solutions:**
1. Verify the thumbprint is correct (check Azure AD or certificate store)
2. Remove any spaces or colons from the thumbprint
3. Ensure certificate is in the correct store (`CurrentUser/My` vs `LocalMachine/My`)
4. On Windows, verify in Certificate Manager (`certmgr.msc`)

**PowerShell to find certificates:**
```powershell
Get-ChildItem -Path Cert:\CurrentUser\My | Format-Table Subject, Thumbprint
```

---

### Problem: "TenantId not configured"

**Symptoms:**
```
❌ TenantId not configured in appsettings.json
```

**Solutions:**
1. Edit `appsettings.json` 
2. Replace `YOUR_TENANT_ID_HERE` with your actual tenant ID
3. Ensure you saved the file

---

### Problem: "Insufficient privileges to complete the operation"

**Symptoms:**
```
AADSTS50034: Insufficient privileges to complete the operation
```

**Solutions:**
1. Verify you granted **admin consent** for API permissions in Azure AD
2. Check that permissions are **Application permissions**, not Delegated
3. Wait a few minutes after granting consent (propagation delay)

---

### Problem: API call returns 401 Unauthorized

**Symptoms:**
```
Response Status: 401 Unauthorized
```

**Solutions:**
1. Verify the API permissions include the required scope (e.g., `User.Read.All`)
2. Ensure admin consent was granted
3. Check that the token hasn't expired
4. Verify the API endpoint is correct

---

### Problem: Token doesn't have `cnf` claim

**Symptoms:**
```
⚠ No confirmation (cnf) claim found
This might be a bearer token, not a PoP token
```

**Solutions:**
1. Ensure you're calling `.WithAtPop()` in the code
2. Verify `.WithExperimentalFeatures()` is called on the app builder
3. Check that Azure AD supports PoP tokens for your tenant
4. This might indicate Azure AD returned a bearer token instead of PoP

---

### Problem: "Could not load type Microsoft.Identity.Web.MsAuth10AtPop"

**Symptoms:**
```
TypeLoadException: Could not load type 'Microsoft.Identity.Web.MsAuth10AtPop'
```

**Solutions:**
1. Ensure the project references are correct
2. Rebuild the solution: `dotnet build`
3. Check that Microsoft.Identity.Web.TokenAcquisition project is up to date

---

## Security Considerations

### For Testing/Development

✅ **Safe for Testing:**
- Using self-signed certificates in development
- Storing thumbprint in appsettings.json
- Running on local machine

❌ **NOT for Production:**
- Hardcoded credentials in source code
- Committing appsettings.json with secrets to Git
- Using weak certificates or keys

### For Production

**Best Practices:**
1. **Use Azure Key Vault** for certificate storage
   ```json
   "ClientCertificates": [{
     "SourceType": "KeyVault",
     "KeyVaultUrl": "https://myvault.vault.azure.net",
     "KeyVaultCertificateName": "my-cert"
   }]
   ```

2. **Use Managed Identity** when running on Azure
3. **Store configuration in**:
   - Azure App Configuration
   - Environment variables
   - Azure Key Vault

4. **Rotate certificates** regularly (every 12-24 months)

5. **Monitor token usage** with Azure AD logs

### PoP Token Security Benefits

The MSAuth 1.0 PoP tokens provide:

- ✅ **Token theft protection** - Stolen tokens are useless without private key
- ✅ **Replay attack mitigation** - Each request requires cryptographic proof
- ✅ **Man-in-the-middle resistance** - Intercepted tokens can't be reused
- ✅ **No token caching risks** - Even cached tokens require key possession

---

## Additional Resources

### Documentation

- [Microsoft Identity Web Wiki](https://github.com/AzureAD/microsoft-identity-web/wiki)
- [Azure AD OAuth 2.0 Documentation](https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph API Reference](https://learn.microsoft.com/graph/api/overview)

### Related Files in Repository

- `ai-notes/ms-auth-notes/01-msauth10-overview.md` - Protocol overview
- `ai-notes/ms-auth-notes/02-technical-implementation.md` - Implementation details
- `ai-notes/ms-auth-notes/03-security-architecture.md` - Security analysis
- `ai-notes/ms-auth-notes/05-integration-guide.md` - Integration guide

### Support

For issues specific to this demo:
- File an issue in the repository

For general Microsoft Identity Web questions:
- [Stack Overflow](https://stackoverflow.com/questions/tagged/microsoft-identity-web)
- [Microsoft Q&A](https://learn.microsoft.com/answers/)

---

## Next Steps

After successfully running this demo:

1. **Experiment with different APIs**
   - Modify the `TestEndpoint` in appsettings.json
   - Try different Microsoft Graph endpoints

2. **Inspect network traffic**
   - Use Fiddler or browser dev tools to see the PoP token in action
   - Compare with bearer token behavior

3. **Implement in your application**
   - Use this code as a reference for your production app
   - Follow production security best practices

4. **Explore advanced scenarios**
   - Token caching strategies
   - Key rotation mechanisms
   - Multiple API calls with single token

---

**Last Updated:** November 2025
**MSAuth 1.0 Version:** 1.0
**Microsoft.Identity.Web Version:** 3.x+
