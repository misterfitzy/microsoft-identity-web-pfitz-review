# MSAuth 1.0 Proof of Concept

This folder contains a complete demonstration application for **MSAuth 1.0 AT-POP** (Access Token Proof-of-Possession) protocol.

## What's Included

```
msauth1.0_poc/
├── MSAuth10PocApp/              # Console application project
│   ├── Program.cs               # Main application code
│   ├── MSAuth10PocApp.csproj   # Project file
│   └── appsettings.json        # Configuration template
├── setup-azure.ps1              # Automated setup script (Windows)
├── setup-azure.sh               # Automated setup script (Linux/macOS)
├── TEST_SETUP_GUIDE.md         # Comprehensive setup guide
└── README.md                   # This file
```

## Quick Start

### Option A: Automated Setup (Recommended) 🚀

The easiest way to get started is using our automated setup scripts that handle Azure AD configuration for you.

#### Windows (PowerShell)

```powershell
# Run from the msauth1.0_poc folder
.\setup-azure.ps1
```

#### Linux/macOS (Bash)

```bash
# Run from the msauth1.0_poc folder
./setup-azure.sh
```

**What the scripts do:**
- ✅ Login to your Azure tenant
- ✅ Create app registration in Azure AD
- ✅ Configure Microsoft Graph API permissions
- ✅ Generate self-signed certificate
- ✅ Upload certificate to app registration
- ✅ Grant admin consent
- ✅ Update appsettings.json with your configuration

**Requirements:**
- Azure CLI installed ([Download](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli))
- Admin access to Azure AD tenant
- PowerShell 5.1+ (Windows) or Bash (Linux/macOS)
- OpenSSL (for Linux/macOS certificate generation)

After the script completes, simply run:
```bash
cd MSAuth10PocApp
dotnet run
```

### Option B: Manual Setup

### 1. Prerequisites
- .NET 8.0 SDK or later
- Azure AD tenant with admin access
- Self-signed certificate (instructions in setup guide)

### 2. Setup Steps

1. **Read the setup guide**: `TEST_SETUP_GUIDE.md` (comprehensive instructions)

2. **Register Azure AD application**:
   - Navigate to Azure Portal > Azure AD > App registrations
   - Create new registration
   - Configure API permissions (Microsoft Graph)
   - Upload certificate
   - Grant admin consent

3. **Create a certificate**:
   ```powershell
   # Windows PowerShell
   $cert = New-SelfSignedCertificate -Subject "CN=MSAuth10PocApp" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable
   Export-Certificate -Cert $cert -FilePath "MSAuth10PocApp.cer"
   ```

4. **Configure the application**:
   - Edit `MSAuth10PocApp/appsettings.json`
   - Update TenantId, ClientId, and CertificateThumbprint

5. **Run the application**:
   ```bash
   cd MSAuth10PocApp
   dotnet run
   ```

## What This Demo Does

The application demonstrates the complete MSAuth 1.0 AT-POP flow:

1. **Generates PoP Key Pair** - Creates an RSA 2048-bit key pair for proof-of-possession
2. **Acquires PoP Token** - Requests a token from Azure AD bound to the public key
3. **Inspects Token** - Validates the `cnf` (confirmation) claim binding
4. **Calls API** - Uses the PoP token to call Microsoft Graph API

## Expected Output

```
===========================================
MSAuth 1.0 AT-POP Demonstration Application
===========================================

✓ Configuration validated
  Tenant ID: 87654321-...
  Client ID: 12345678-...

[Step 1] Generating PoP key pair...
✓ Generated RSA key pair

[Step 2] Acquiring MSAuth 1.0 PoP token...
✓ Successfully acquired PoP token
  Token Type: pop

[Step 3] Inspecting PoP access token...
  ✓ Confirmation (cnf) claim found
    This proves the token is bound to the PoP key!

[Step 4] Making API call with PoP token...
✓ API call successful!

===========================================
✓ MSAuth 1.0 demonstration completed successfully!
===========================================
```

## Key Features Demonstrated

### PoP Token Acquisition
- Uses `WithAtPop()` extension method
- Passes public key as JWK in `req_cnf` parameter
- Receives token bound to the public key

### Security Benefits
- **Token Theft Protection** - Stolen tokens are useless without the private key
- **Replay Attack Mitigation** - Cryptographic proof required for each use
- **Enhanced Security** - Significant improvement over bearer tokens

### Code Highlights

```csharp
// Generate PoP key pair
var rsa = RSA.Create(2048);
var jwk = CreateJwk(rsa);

// Acquire PoP token with MSAuth 1.0
var result = await app
    .AcquireTokenForClient(scopes)
    .WithAtPop(keyId, jwk)  // MSAuth 1.0 extension
    .ExecuteAsync();

// Token is now bound to the public key!
```

## Documentation

- **[TEST_SETUP_GUIDE.md](TEST_SETUP_GUIDE.md)** - Complete setup instructions
- **[MSAuth 1.0 Overview](../ai-notes/ms-auth-notes/01-msauth10-overview.md)** - Protocol documentation
- **[Technical Implementation](../ai-notes/ms-auth-notes/02-technical-implementation.md)** - Deep dive
- **[Security Architecture](../ai-notes/ms-auth-notes/03-security-architecture.md)** - Security analysis

## Troubleshooting

### Certificate Not Found
```
❌ Certificate not found with thumbprint: ...
```
**Solution**: Check thumbprint in appsettings.json and verify certificate is installed

### Configuration Not Set
```
❌ TenantId not configured in appsettings.json
```
**Solution**: Update appsettings.json with your Azure AD tenant details

### Admin Consent Required
```
AADSTS50034: Insufficient privileges to complete the operation
```
**Solution**: Grant admin consent for API permissions in Azure AD

See **TEST_SETUP_GUIDE.md** for comprehensive troubleshooting.

## Architecture

```
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  MSAuth10PocApp  │          │  Azure AD        │          │  Microsoft Graph │
│  (This App)      │          │  (eSTS)          │          │  API             │
└────────┬─────────┘          └────────┬─────────┘          └────────┬─────────┘
         │                              │                              │
         │ 1. Generate RSA Key Pair     │                              │
         │    (2048-bit)                │                              │
         │                              │                              │
         │ 2. Token Request             │                              │
         │    + req_cnf (public key)    │                              │
         │    + token_type=pop          │                              │
         │    + client_assertion        │                              │
         │─────────────────────────────►│                              │
         │                              │                              │
         │                              │ 3. Validate & Bind           │
         │                              │    Token to Key              │
         │                              │                              │
         │ 4. PoP Access Token          │                              │
         │    (bound to public key)     │                              │
         │◄─────────────────────────────┤                              │
         │                              │                              │
         │ 5. API Request + PoP Token   │                              │
         │──────────────────────────────┼─────────────────────────────►│
         │                              │                              │
         │                              │                              │ 6. Validate
         │                              │                              │    Token +
         │                              │                              │    Binding
         │                              │                              │
         │ 7. Protected Resource        │                              │
         │◄─────────────────────────────┼──────────────────────────────┤
```

## Related Code

The MSAuth 1.0 implementation used by this demo is located in:
- `src/Microsoft.Identity.Web.TokenAcquisition/MsAuth10AtPop.cs` - Extension method
- `src/Microsoft.Identity.Web.TokenAcquisition/AtPopOperation.cs` - Core implementation
- `tests/Microsoft.Identity.Web.Test/MsAuth10AtPopTests.cs` - Unit tests

## Security Notes

⚠️ **This is a demonstration application for testing and learning purposes.**

For production use:
- Use Azure Key Vault for certificate storage
- Implement proper key rotation
- Use Managed Identity when running on Azure
- Store configuration in secure locations (Key Vault, App Configuration)
- Monitor token usage with Azure AD logs

## Support

For issues or questions:
- **Setup Issues**: See TEST_SETUP_GUIDE.md troubleshooting section
- **MSAuth 1.0 Protocol**: See ai-notes/ms-auth-notes/ documentation
- **Microsoft Identity Web**: https://github.com/AzureAD/microsoft-identity-web/wiki

## License

Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT License.
