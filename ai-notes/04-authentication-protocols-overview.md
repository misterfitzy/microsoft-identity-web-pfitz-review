# Authentication Protocols Overview: Microsoft Identity Web

## Executive Summary

Microsoft Identity Web implements **OAuth 2.0** and **OpenID Connect (OIDC)** as primary authentication protocols, with support for advanced extensions including **Proof-of-Possession (PoP)**, **JWT Bearer**, **Client Assertions**, and **Federated Identity Credentials**. The library serves as an abstraction layer over the Microsoft Authentication Library (MSAL.NET), providing ASP.NET Core-native integration.

## Protocol Stack Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Application Layer (ASP.NET Core)                │
├─────────────────────────────────────────────────────────┤
│     Microsoft.Identity.Web (This Library)               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  - Token Acquisition Orchestration                │  │
│  │  - Middleware Integration (OIDC, JWT Bearer)      │  │
│  │  - Authorization Policy Enforcement               │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│     MSAL.NET (Microsoft.Identity.Client)                │
│  ┌───────────────────────────────────────────────────┐  │
│  │  - OAuth 2.0 Protocol Implementation              │  │
│  │  - Token Cache Management                         │  │
│  │  - Cryptographic Operations                       │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│     Transport Layer (HTTPS/TLS 1.2+)                    │
├─────────────────────────────────────────────────────────┤
│     Azure AD / Azure AD B2C / Microsoft Identity        │
│              Platform (Authorization Server)             │
└─────────────────────────────────────────────────────────┘
```

## Core Authentication Protocols

### 1. OpenID Connect (OIDC) 1.0

**Use Case**: User authentication in web applications (sign-in scenarios)

#### Protocol Specification
- **Standard**: OpenID Connect Core 1.0
- **Base Protocol**: OAuth 2.0 Authorization Code Flow
- **Extension**: ID Token (JWT containing user identity claims)

#### Flow Implementation

**Location**: `src/Microsoft.Identity.Web/WebAppExtensions/MicrosoftIdentityWebAppAuthenticationBuilderExtensions.cs`

```
┌─────────┐                                           ┌──────────────┐
│         │                                           │              │
│ Browser │                                           │   Azure AD   │
│         │                                           │              │
└────┬────┘                                           └──────┬───────┘
     │                                                       │
     │  1. User navigates to protected resource             │
     │────────────────────────────────────────────>         │
     │                                                       │
     │  2. HTTP 302 Redirect to Azure AD                    │
     │  /authorize?client_id=...&redirect_uri=...           │
     │  &response_type=code&scope=openid+profile            │
     │  &code_challenge=...&code_challenge_method=S256      │
     │<────────────────────────────────────────────         │
     │                                                       │
     │  3. User authenticates + consents                    │
     │────────────────────────────────────────────>         │
     │                                                       │
     │  4. HTTP 302 Redirect back with auth code            │
     │  /signin-oidc?code=...&state=...                     │
     │<────────────────────────────────────────────         │
     │                                                       │
┌────┴────┐                                           ┌──────┴───────┐
│         │                                           │              │
│ Web App │  5. POST /token (code + code_verifier)   │   Azure AD   │
│         │──────────────────────────────────────────>│              │
│         │                                           │              │
│         │  6. Response: access_token, id_token,     │              │
│         │     refresh_token                         │              │
│         │<──────────────────────────────────────────│              │
└─────────┘                                           └──────────────┘
```

#### Key Components

**Authorization Request Builder**:
```csharp
// Triggered by: OnRedirectToIdentityProvider event
// Location: OpenIdConnectMiddlewareDiagnostics.cs

Parameters sent to Azure AD:
- client_id: Application (client) ID
- redirect_uri: Callback URL (must be registered)
- response_type: "code" (authorization code flow)
- response_mode: "form_post" or "query"
- scope: "openid profile email" + custom scopes
- state: CSRF token (validated on callback)
- nonce: Replay protection for ID token
- code_challenge: SHA256(code_verifier) [PKCE]
- code_challenge_method: "S256"
- prompt: "select_account", "login", "consent", "none"
```

**Token Request Handler**:
```csharp
// Triggered by: OnAuthorizationCodeReceived event
// Implementation: TokenAcquisition.AddAccountToCacheFromAuthorizationCodeAsync()

POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id={clientId}
&code={authorizationCode}
&redirect_uri={redirectUri}
&code_verifier={codeVerifier}
&client_secret={secret} OR client_assertion={jwt}
&scope={scopes}
```

**ID Token Validation**:
```csharp
// Handler: OnTokenValidated event
// Validates:
1. Signature (RSA/ECDSA using Azure AD public keys)
2. Issuer (iss claim matches expected tenant)
3. Audience (aud claim matches client ID)
4. Expiration (exp claim > current time)
5. Not before (nbf claim < current time)
6. Nonce (matches request nonce)
7. Issued at time (iat claim)

// Result: ClaimsPrincipal with user identity
```

#### OIDC Claims in ID Token

Standard claims processed:
- `sub`: Subject (unique user identifier)
- `name`: User's display name
- `preferred_username`: Email or UPN
- `oid`: Object ID (Azure AD user ID)
- `tid`: Tenant ID
- `email`: Email address
- `roles`: Azure AD app roles assigned to user

### 2. OAuth 2.0 Authorization Code Flow with PKCE

**Use Case**: Secure authorization code exchange (prevents authorization code interception)

#### PKCE Extension (RFC 7636)

**Purpose**: Mitigates authorization code interception attacks

**Implementation**: Automatic in `MicrosoftIdentityWebAppAuthenticationBuilderExtensions`

```csharp
// 1. Generate code verifier (random string)
string codeVerifier = GenerateRandomString(128); // Cryptographically random

// 2. Generate code challenge
string codeChallenge = Base64UrlEncode(SHA256(codeVerifier));

// 3. Authorization request includes code_challenge
GET /authorize?code_challenge={codeChallenge}&code_challenge_method=S256

// 4. Token request includes code_verifier
POST /token
grant_type=authorization_code&code={code}&code_verifier={codeVerifier}

// 5. Azure AD validates: SHA256(code_verifier) == code_challenge
```

**Security Benefit**: Even if attacker intercepts authorization code, cannot exchange it without code_verifier

### 3. OAuth 2.0 Client Credentials Flow

**Use Case**: Service-to-service authentication (daemon apps, background jobs)

**Location**: `TokenAcquisition.GetAccessTokenForAppAsync()`

#### Flow Diagram

```
┌──────────────┐                              ┌──────────────┐
│              │                              │              │
│ Service App  │                              │   Azure AD   │
│              │                              │              │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  POST /token                                │
       │  grant_type=client_credentials              │
       │  client_id={clientId}                       │
       │  client_secret={secret}                     │
       │    OR client_assertion={signedJWT}          │
       │  scope={resource}/.default                  │
       │────────────────────────────────────────────>│
       │                                             │
       │  Response:                                  │
       │  {                                          │
       │    "access_token": "eyJ0eXAi...",          │
       │    "token_type": "Bearer",                  │
       │    "expires_in": 3599                       │
       │  }                                          │
       │<────────────────────────────────────────────│
       │                                             │
```

#### Client Authentication Methods

**1. Client Secret (Shared Secret)**
```csharp
POST /token
client_id={clientId}
&client_secret={secret}
&grant_type=client_credentials
&scope=https://graph.microsoft.com/.default
```

**Security Level**: Medium (secret can be compromised)

**2. Client Certificate (X.509)**
```csharp
// Certificate-based authentication
POST /token
client_id={clientId}
&client_assertion={base64UrlEncoded(JWT)}
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&grant_type=client_credentials
&scope=https://graph.microsoft.com/.default

// JWT client assertion signed with private key
{
  "alg": "RS256",
  "typ": "JWT",
  "x5t": "{thumbprint}"
}.
{
  "aud": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
  "iss": "{clientId}",
  "sub": "{clientId}",
  "jti": "{unique-id}",
  "exp": 1234567890,
  "nbf": 1234567800
}.
{signature}
```

**Security Level**: High (private key required)  
**Implementation**: `DefaultCredentialsLoader.CustomSignedAssertion.cs`

**3. Managed Identity (No Secret)**
```csharp
// Azure Managed Identity flow
// No client_secret or client_assertion needed
// Implementation: TokenAcquisition.ManagedIdentity.cs

// Step 1: Get MI token from Azure Instance Metadata Service
GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01
    &resource=https://vault.azure.net
Metadata: true

// Step 2: Use MI token to authenticate to Azure AD
POST /token
client_id={managedIdentityClientId}
&client_assertion={miToken}
&grant_type=client_credentials
&scope=https://graph.microsoft.com/.default
```

**Security Level**: Highest (no credential storage)

### 4. OAuth 2.0 On-Behalf-Of (OBO) Flow

**Use Case**: Web API calling downstream API on user's behalf

**Location**: `TokenAcquisition.GetAccessTokenForUserAsync()`

#### Flow Diagram

```
┌────────┐         ┌──────────────┐         ┌──────────────┐         ┌──────────┐
│        │         │              │         │              │         │          │
│ Client │         │  Web API A   │         │   Azure AD   │         │Web API B │
│        │         │              │         │              │         │          │
└───┬────┘         └──────┬───────┘         └──────┬───────┘         └────┬─────┘
    │                     │                        │                      │
    │  1. Call API A      │                        │                      │
    │  Authorization:     │                        │                      │
    │  Bearer {token1}    │                        │                      │
    │────────────────────>│                        │                      │
    │                     │                        │                      │
    │                     │  2. OBO token request  │                      │
    │                     │  grant_type=urn:...    │                      │
    │                     │  :on-behalf-of         │                      │
    │                     │  assertion={token1}    │                      │
    │                     │  scope=api://B/.default│                      │
    │                     │───────────────────────>│                      │
    │                     │                        │                      │
    │                     │  3. Access token2      │                      │
    │                     │<───────────────────────│                      │
    │                     │                        │                      │
    │                     │  4. Call API B                                │
    │                     │  Authorization: Bearer {token2}               │
    │                     │──────────────────────────────────────────────>│
    │                     │                        │                      │
    │                     │  5. Response           │                      │
    │                     │<──────────────────────────────────────────────│
    │                     │                        │                      │
    │  6. Response        │                        │                      │
    │<────────────────────│                        │                      │
    │                     │                        │                      │
```

#### OBO Token Request

```csharp
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&client_id={clientId}
&client_secret={secret} OR client_assertion={jwt}
&assertion={incomingAccessToken}  // User's access token
&scope=api://downstream-api/.default
&requested_token_use=on_behalf_of
```

**Key Validation**: Azure AD validates that:
1. Incoming token is valid and not expired
2. Audience of incoming token matches client_id
3. User consented to scopes being requested
4. Client is authorized to act on user's behalf

**Cache Behavior**: OBO tokens cached by user + scopes (enables efficient downstream calls)

### 5. Azure AD B2C Custom Policies (User Flows)

**Use Case**: Consumer authentication with social providers and custom UX

**Location**: `AzureADB2COpenIDConnectEventHandlers.cs`, `MicrosoftIdentityOptions`

#### B2C-Specific Parameters

```csharp
public class MicrosoftIdentityOptions : OpenIdConnectOptions
{
    // B2C user flows (policies)
    public string? SignUpSignInPolicyId { get; set; }  // e.g., "B2C_1_susi"
    public string? EditProfilePolicyId { get; set; }   // e.g., "B2C_1_edit_profile"
    public string? ResetPasswordPolicyId { get; set; } // e.g., "B2C_1_password_reset"
}
```

#### Policy Switching Flow

```csharp
// User clicks "Edit Profile" link
// Event: OnRedirectToIdentityProvider

if (context.Properties.Items.ContainsKey("policy"))
{
    var policy = context.Properties.Items["policy"];
    context.ProtocolMessage.Parameters.Add("p", policy);
    context.ProtocolMessage.IssuerAddress = 
        $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/oauth2/v2.0/authorize";
}

// Azure AD B2C executes the specified user flow
// Returns to callback with claims from that policy
```

**B2C Authorization Endpoint Pattern**:
```
https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/oauth2/v2.0/authorize
```

#### Social Provider Integration

B2C handles provider-specific protocols:
- Google: OAuth 2.0
- Facebook: OAuth 2.0
- Microsoft Account: OIDC
- Azure AD (federation): OIDC/SAML
- Custom OIDC providers: Generic OIDC

**From app perspective**: Always OIDC (B2C abstracts provider differences)

### 6. JWT Bearer Authentication

**Use Case**: Web API token validation

**Location**: `src/Microsoft.Identity.Web/WebApiExtensions/MicrosoftIdentityWebApiAuthenticationBuilderExtensions.cs`

#### Token Validation Pipeline

```csharp
// 1. Extract token from Authorization header
string token = Request.Headers["Authorization"]
    .ToString()
    .Replace("Bearer ", "");

// 2. Download Azure AD signing keys (cached)
var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    new OpenIdConnectConfigurationRetriever());

// 3. Validate JWT
var validationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuers = new[] { 
        "https://login.microsoftonline.com/{tenant}/v2.0",
        "https://sts.windows.net/{tenant}/"
    },
    
    ValidateAudience = true,
    ValidAudiences = new[] { 
        "{clientId}",
        "api://{clientId}"
    },
    
    ValidateLifetime = true,
    ClockSkew = TimeSpan.FromMinutes(5),
    
    ValidateIssuerSigningKey = true,
    IssuerSigningKeys = config.SigningKeys
};

var handler = new JwtSecurityTokenHandler();
ClaimsPrincipal principal = handler.ValidateToken(
    token, 
    validationParameters, 
    out SecurityToken validatedToken);

// 4. Attach principal to HttpContext
HttpContext.User = principal;
```

**Validation Checks**:
1. ✅ Signature validation (cryptographic)
2. ✅ Issuer validation (trusted Azure AD tenant)
3. ✅ Audience validation (token intended for this API)
4. ✅ Expiration validation (not expired)
5. ✅ Not-before validation (token active)
6. ✅ Algorithm validation (only RS256, RS384, RS512, ES256, ES384, ES512)

### 7. Proof-of-Possession (PoP) Tokens

**Use Case**: High-security scenarios requiring token binding

**Location**: `src/Microsoft.Identity.Web.TokenAcquisition/MsAuth10AtPop.cs`

#### PoP Protocol Flow

```
┌──────────────┐                              ┌──────────────┐
│              │                              │              │
│  Client App  │                              │   Azure AD   │
│              │                              │              │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  1. Generate ephemeral key pair             │
       │     (RSA 2048 or EC P-256)                  │
       │                                             │
       │  2. POST /token with PoP extension          │
       │     req_cnf: {jwk: {public key}}            │
       │     token_type: pop                         │
       │────────────────────────────────────────────>│
       │                                             │
       │  3. PoP Access Token                        │
       │     (contains cnf claim with key binding)   │
       │<────────────────────────────────────────────│
       │                                             │
┌──────┴───────┐                              ┌──────┴───────┐
│              │                              │              │
│  Client App  │                              │  Resource    │
│              │                              │  Server      │
│              │                              │              │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  4. API Request with PoP proof              │
       │     Authorization: PoP {access_token}       │
       │     Signature: {signed HTTP request}        │
       │────────────────────────────────────────────>│
       │                                             │
       │                                             │  5. Validate
       │                                             │     - Token
       │                                             │     - Signature
       │                                             │     - Binding
       │                                             │
       │  6. API Response                            │
       │<────────────────────────────────────────────│
       │                                             │
```

#### PoP Token Structure

**Access Token cnf Claim**:
```json
{
  "typ": "pop",
  "alg": "RS256",
  "kid": "key-id-123"
}.
{
  "aud": "api://resource-server",
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
  "exp": 1234567890,
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
      "e": "AQAB"
    }
  }
}
```

**Signed HTTP Request (Proof)**:
```
POST /api/data HTTP/1.1
Host: api.example.com
Authorization: PoP eyJ0eXAiOiJKV1QiLCJhbGc...
Signature: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwX21ldGhvZCI6IlBPU1QiLCJodHRwX3BhdGgiOiIvYXBpL2RhdGEiLCJob3N0IjoiYXBpLmV4YW1wbGUuY29tIiwidGltZXN0YW1wIjoxNjg5NTg1MDAwfQ.signature

// Signature JWT:
{
  "alg": "RS256"
}.
{
  "http_method": "POST",
  "http_path": "/api/data",
  "host": "api.example.com",
  "timestamp": 1689585000,
  "at": "SHA256(access_token)"
}.
{signature using private key}
```

**Security Properties**:
- Token cannot be used without private key
- Each request must be signed (prevents replay)
- Timestamp prevents old signatures from being reused

## Advanced Authentication Extensions

### 8. Managed Identity Authentication

**Protocol**: OAuth 2.0 Client Credentials with Azure Instance Metadata Service (IMDS)

**Flow**:
```
1. App running on Azure VM/App Service/AKS
2. HTTP GET to http://169.254.169.254/metadata/identity/oauth2/token
   Headers: Metadata: true
3. IMDS returns short-lived JWT (signed by Azure)
4. App presents JWT to Azure AD as client assertion
5. Azure AD validates JWT and issues access token
6. No secrets stored in application
```

**Implementation**: `TokenAcquisition.ManagedIdentity.cs`

### 9. Workload Identity Federation (Kubernetes)

**Protocol**: OIDC Token Exchange (RFC 8693 variant)

**Flow**:
```
1. K8s mounts service account token to pod: /var/run/secrets/azure/tokens/azure-identity-token
2. App reads service account token (OIDC JWT issued by AKS)
3. App sends token exchange request to Azure AD:
   POST /token
   grant_type=client_credentials
   client_assertion={k8s_service_account_token}
   client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
   scope={resource}/.default
4. Azure AD validates:
   - Token signature (from AKS OIDC issuer)
   - Federated credential configured in app registration
   - Subject claim matches expected service account
5. Azure AD issues access token for requested resource
```

**Security**: Eliminates secrets in containers, auto-rotates K8s tokens

**Implementation**: `AzureIdentityForKubernetesClientAssertion.cs`

### 10. Federated Identity Credentials (Cross-Cloud)

**Protocol**: OIDC Token Exchange

**Use Case**: GitHub Actions, GitLab CI, AWS, GCP workloads accessing Azure

**Example: GitHub Actions**:
```yaml
# GitHub workflow
- uses: azure/login@v1
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

# Behind the scenes:
1. GitHub issues OIDC token for workflow
2. Azure CLI requests token from Azure AD
3. Presents GitHub OIDC token as client assertion
4. Azure AD validates federated credential trust
5. Issues Azure access token
```

**Configuration**: Azure AD app registration → Certificates & secrets → Federated credentials

## Protocol Version Support

| Protocol | Version | Endpoints |
|----------|---------|-----------|
| **OAuth 2.0** | RFC 6749 + extensions | v1.0, v2.0 |
| **OpenID Connect** | 1.0 | v1.0, v2.0 |
| **PKCE** | RFC 7636 | v1.0, v2.0 |
| **JWT** | RFC 7519 | Both |
| **Token Introspection** | RFC 7662 | Not implemented |
| **Token Revocation** | RFC 7009 | Via Azure AD |
| **Device Code** | RFC 8628 | Via MSAL.NET |
| **Resource Owner Password** | RFC 6749 (deprecated) | ❌ Not supported |

## Security Protocol Features

### Token Lifetimes

| Token Type | Default Lifetime | Renewable | Revocable |
|------------|------------------|-----------|-----------|
| **Access Token** | 1 hour | No | Via refresh token revocation |
| **ID Token** | 1 hour | No | N/A (stateless) |
| **Refresh Token** | 90 days (default) | Yes (rolling) | Yes (immediate) |
| **PoP Token** | 1 hour | No | Via refresh token revocation |

### Cryptographic Algorithms

**Supported Signing Algorithms** (Azure AD):
- RS256 (RSA SHA-256) - Default
- RS384 (RSA SHA-384)
- RS512 (RSA SHA-512)
- ES256 (ECDSA P-256 SHA-256)
- ES384 (ECDSA P-384 SHA-384)
- ES512 (ECDSA P-521 SHA-512)

**NOT Supported** (security reasons):
- HS256 (HMAC SHA-256) - Symmetric key, not used by Azure AD
- None (unsigned) - Rejected

**Key Rotation**: Azure AD rotates signing keys every 6 weeks, libraries auto-fetch new keys

## Multi-Tenant Considerations

### Issuer Validation Strategies

**Single Tenant** (most secure):
```csharp
ValidIssuers = new[] {
    $"https://login.microsoftonline.com/{tenantId}/v2.0",
    $"https://sts.windows.net/{tenantId}/"
}
```

**Multi-Tenant** (ISV scenario):
```csharp
// Custom issuer validation
IssuerValidator = (issuer, token, parameters) =>
{
    // Extract tenant ID from issuer
    var tenantId = ExtractTenantId(issuer);
    
    // Check against allowlist (database, config, etc.)
    if (IsAllowedTenant(tenantId))
        return issuer;
    
    throw new SecurityTokenInvalidIssuerException($"Issuer {issuer} not allowed");
}
```

**Common Tenant** (any Azure AD user):
```csharp
// Use "common" authority (relaxed validation)
Authority = "https://login.microsoftonline.com/common/v2.0"

// Application must validate tenant in business logic
```

## Protocol Comparison Matrix

| Feature | OIDC Web App | JWT Bearer API | Client Credentials | OBO Flow | Managed Identity |
|---------|--------------|----------------|--------------------|-----------|-|
| **User Context** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | ❌ No |
| **Refresh Tokens** | ✅ Yes | ❌ No | ❌ No | ✅ Yes | ✅ Yes (implicit) |
| **Interactive Auth** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| **Requires Secret** | ✅ Yes | ❌ No (validates only) | ✅ Yes* | ✅ Yes | ❌ No |
| **Token Type** | ID + Access | Access | Access | Access | Access |
| **Use Case** | Sign-in | API protection | Daemon | API chaining | Azure services |

\* Unless using Managed Identity

## Conclusion

Microsoft Identity Web provides comprehensive support for modern authentication protocols:

1. **OAuth 2.0**: Complete implementation of all relevant grant types
2. **OIDC**: Full support for user authentication and SSO
3. **Security Extensions**: PKCE, PoP, client assertions
4. **Cloud-Native**: Managed Identity, Workload Identity Federation
5. **Enterprise-Ready**: Multi-tenant, B2B, B2C scenarios

The library abstracts protocol complexity while maintaining security and flexibility, enabling developers to implement enterprise-grade authentication with minimal code.

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-22  
**Standards References**: RFC 6749, RFC 6750, RFC 7636, OIDC Core 1.0
