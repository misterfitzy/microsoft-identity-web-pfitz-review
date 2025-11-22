# Token Authentication Protocols: Detailed Technical Documentation

## Table of Contents

1. [Token Types and Formats](#token-types-and-formats)
2. [Token Acquisition Flows](#token-acquisition-flows)
3. [Token Validation and Verification](#token-validation-and-verification)
4. [Token Caching Strategies](#token-caching-strategies)
5. [Token Security Mechanisms](#token-security-mechanisms)
6. [Advanced Token Scenarios](#advanced-token-scenarios)
7. [Token Lifecycle Management](#token-lifecycle-management)

---

## Token Types and Formats

### 1. ID Token (OIDC Identity Token)

**Purpose**: Proves user identity to the application after authentication

**Format**: JSON Web Token (JWT) - Signed

**Structure**:
```json
{
  // HEADER
  "typ": "JWT",
  "alg": "RS256",
  "kid": "1e9gdk7"
}.
{
  // PAYLOAD
  "iss": "https://login.microsoftonline.com/{tenantId}/v2.0",
  "aud": "{clientId}",
  "exp": 1689585600,
  "iat": 1689582000,
  "nbf": 1689582000,
  "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
  "oid": "00000000-0000-0000-66f3-3332eca7ea81",
  "tid": "9188040d-6c67-4c5b-b112-36a304b66dad",
  "preferred_username": "user@contoso.com",
  "name": "John Doe",
  "nonce": "12345",
  "ver": "2.0"
}.
{
  // SIGNATURE
  "signature_bytes"
}
```

**Key Claims**:

| Claim | Description | Security Relevance |
|-------|-------------|-------------------|
| `iss` | Issuer (Azure AD tenant) | **Critical**: Validates token source |
| `aud` | Audience (application client ID) | **Critical**: Prevents token misuse |
| `exp` | Expiration timestamp | **Critical**: Prevents replay after expiry |
| `nbf` | Not-before timestamp | Prevents premature token use |
| `iat` | Issued-at timestamp | Audit trail |
| `sub` | Subject (unique user identifier) | Stable user ID across tenants |
| `oid` | Object ID (Azure AD user ID) | Primary user identifier |
| `tid` | Tenant ID | Multi-tenant app context |
| `nonce` | Cryptographic nonce | **Critical**: Replay attack prevention |
| `preferred_username` | User's email/UPN | Display purposes (not stable) |
| `name` | Display name | UI display |
| `roles` | App roles assigned to user | Authorization decisions |

**Usage in Code**:
```csharp
// Location: OpenIdConnectMiddlewareDiagnostics.OnTokenValidated
ClaimsPrincipal user = context.Principal;
string userId = user.FindFirst("oid").Value;
string tenantId = user.FindFirst("tid").Value;
string email = user.FindFirst("preferred_username").Value;
```

**Security Validations Performed**:
1. ✅ Signature verification (RSA/ECDSA)
2. ✅ Issuer whitelist check
3. ✅ Audience match (client ID)
4. ✅ Expiration check (`exp > now`)
5. ✅ Not-before check (`nbf < now`)
6. ✅ Nonce match (from request)
7. ✅ Algorithm validation (no "none" algorithm)

**Token Lifetime**: Typically 1 hour (configurable in Azure AD)

---

### 2. Access Token (OAuth 2.0 Bearer Token)

**Purpose**: Authorizes access to protected resources (APIs)

**Format**: JWT (opaque to client, structured for resource server)

**Structure** (v2.0 tokens):
```json
{
  // HEADER
  "typ": "JWT",
  "alg": "RS256",
  "kid": "1e9gdk7"
}.
{
  // PAYLOAD
  "aud": "api://00000003-0000-0000-c000-000000000000", // Resource API
  "iss": "https://login.microsoftonline.com/{tenantId}/v2.0",
  "iat": 1689582000,
  "nbf": 1689582000,
  "exp": 1689585600,
  "aio": "...",
  "azp": "{clientId}",  // Authorized party (app that requested token)
  "azpacr": "1",        // Auth context class reference
  "oid": "00000000-0000-0000-66f3-3332eca7ea81",
  "rh": "...",
  "scp": "User.Read Mail.Send", // Delegated permissions (scopes)
  "roles": ["Data.Read.All"],   // Application permissions
  "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
  "tid": "9188040d-6c67-4c5b-b112-36a304b66dad",
  "uti": "...",
  "ver": "2.0",
  "wids": ["62e90394-69f5-4237-9190-012177145e10"] // Admin roles
}.
{
  // SIGNATURE
  "signature_bytes"
}
```

**Key Claims for Authorization**:

| Claim | Type | Description | Authorization Use |
|-------|------|-------------|-------------------|
| `scp` | Delegated | Space-separated scopes | User-delegated API permissions |
| `roles` | Application | Array of app role names | App-only permissions |
| `wids` | Directory | Azure AD admin role IDs | Admin-level authorization |
| `aud` | Core | Audience (API identifier) | **Must match API to accept token** |
| `oid` | Core | User object ID | User-specific data access |
| `tid` | Core | Tenant ID | Multi-tenant data isolation |

**Usage in Code**:
```csharp
// Location: ScopeAuthorizationHandler, JwtBearerMiddlewareDiagnostics

// Extract scopes from token
var scopeClaim = context.User.FindFirst("scp") ?? context.User.FindFirst("scope");
var scopes = scopeClaim?.Value?.Split(' ') ?? Array.Empty<string>();

// Validate required scope
if (!scopes.Contains("access_as_user"))
{
    context.Fail("Insufficient permissions");
}

// Extract roles
var roles = context.User.FindAll("roles").Select(c => c.Value).ToArray();
```

**Validation by Resource Server** (Web API):
```csharp
// Location: JwtBearerMiddlewareDiagnostics.cs
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = "api://{apiClientId}", // Critical: Must match
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };
    });
```

**Token Lifetime**: 1 hour default (non-renewable)

**Important**: Access tokens are **opaque to the client**. Client should never parse or inspect access token claims (use ID token for user identity).

---

### 3. Refresh Token

**Purpose**: Obtain new access tokens without user interaction

**Format**: Opaque string (not JWT) - Encrypted by Azure AD

**Characteristics**:
- Long-lived: 90 days default (configurable up to 1 year)
- Single-use: New refresh token issued with each use (rolling refresh)
- Revocable: Can be revoked via Azure AD portal or API
- Highly sensitive: Equivalent to user credentials

**Security Properties**:
- Encrypted and signed by Azure AD (cannot be forged)
- Bound to specific client ID + user + tenant
- Cannot be used across applications
- Invalidated on password change (configurable)

**Storage Requirements**:
- ✅ **MUST** be stored server-side (never in browser)
- ✅ **MUST** be encrypted at rest (in token cache)
- ✅ **MUST** have restricted access (user-partitioned cache)
- ❌ **NEVER** send to client (JavaScript, mobile app - exception: native apps)

**Usage in Code**:
```csharp
// Location: TokenAcquisition.cs
// Refresh token automatically used by MSAL.NET when access token expires

// Implicit refresh
var accessToken = await tokenAcquisition.GetAccessTokenForUserAsync(
    new[] { "User.Read" });
// If cached access token expired, MSAL uses refresh token transparently

// Explicit refresh (rare)
var result = await confidentialClient
    .AcquireTokenSilent(scopes, account)
    .ExecuteAsync();
```

**Token Rotation**:
```
Initial:  RT1 → AT1 (expires in 1 hour)
Hour 1:   RT1 → AT2 + RT2 (new refresh token issued)
Hour 2:   RT2 → AT3 + RT3 (rolling refresh)
```

**Revocation Scenarios**:
1. User password change
2. Admin revokes user sessions
3. Token lifetime policy exceeded
4. Conditional access policy change
5. Manual revocation via PowerShell/Graph API

---

### 4. Authorization Code

**Purpose**: Intermediate credential in authorization code flow

**Format**: Opaque string (typically 128-256 characters)

**Characteristics**:
- **Single-use**: Can only be redeemed once
- **Short-lived**: Expires in 10 minutes (strict)
- **PKCE-bound**: Must be redeemed with matching code_verifier
- **Redirect-URI-bound**: Must use same redirect_uri as authorization request

**Security Properties**:
- Exposed in browser redirect (URL or form post)
- Cannot be used without:
  - Client authentication (secret or certificate)
  - PKCE code_verifier (prevents interception attacks)
  - Original redirect_uri (prevents redirect attacks)

**Flow**:
```
1. User authenticates → Authorization Code issued
2. Browser redirects to callback with code
3. Server exchanges code for tokens (POST /token)
4. Code is invalidated (single-use)
```

**Code Redemption**:
```csharp
// Location: TokenAcquisition.AddAccountToCacheFromAuthorizationCodeAsync

POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={clientId}
&scope={scopes}
&code={authorizationCode}
&redirect_uri={originalRedirectUri}  // Must match
&grant_type=authorization_code
&code_verifier={pkceCodeVerifier}   // PKCE proof
&client_secret={secret} OR client_assertion={jwt}
```

**Security Attack Mitigation**:

| Attack | Mitigation |
|--------|-----------|
| Code interception | PKCE (attacker lacks code_verifier) |
| Code replay | Single-use enforcement |
| Code theft via redirect manipulation | Redirect URI validation |
| Code used by wrong app | Client authentication required |

---

### 5. Proof-of-Possession (PoP) Token

**Purpose**: Cryptographically bind access token to client key

**Format**: JWT with `cnf` (confirmation) claim

**Structure**:
```json
{
  // HEADER
  "typ": "pop",
  "alg": "RS256",
  "kid": "pop-key-1"
}.
{
  // PAYLOAD (access token claims)
  "aud": "api://resource",
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
  "exp": 1689585600,
  "scp": "User.Read",
  
  // PoP-specific claim
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  }
}.
{
  // SIGNATURE
  "signature_bytes"
}
```

**Signed HTTP Request**:
```http
POST /api/data HTTP/1.1
Host: api.example.com
Authorization: PoP eyJ0eXAiOiJwb3AiLCJhbGc...
Signature: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwX21ldGhvZCI6IlBPU1QiLCJodHRwX3BhdGgiOiIvYXBpL2RhdGEiLCJob3N0IjoiYXBpLmV4YW1wbGUuY29tIiwidGltZXN0YW1wIjoxNjg5NTg1MDAwLCJhdCI6IlNIQTI1NihhdCJ9.PGDm7pJ...

Content-Type: application/json
{"data": "sensitive"}
```

**Signature JWT Payload**:
```json
{
  "http_method": "POST",
  "http_path": "/api/data",
  "host": "api.example.com",
  "timestamp": 1689585000,
  "at": "SHA256(access_token_value)"
}
```

**Validation by Resource Server**:
```csharp
// 1. Extract access token from Authorization header
// 2. Validate access token (standard JWT validation)
// 3. Extract public key from cnf claim
// 4. Extract Signature header
// 5. Verify signature JWT using public key from cnf
// 6. Validate signature JWT claims match request
// 7. Validate timestamp (prevent replay)

public bool ValidatePopRequest(HttpRequest request, string popToken)
{
    // Parse PoP access token
    var handler = new JsonWebTokenHandler();
    var token = handler.ReadJsonWebToken(popToken);
    
    // Extract public key from cnf claim
    var cnfClaim = token.GetClaim("cnf");
    var jwk = JsonWebKey.Create(cnfClaim.Value);
    
    // Extract signature JWT from header
    var signatureJwt = request.Headers["Signature"].ToString();
    
    // Validate signature
    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        IssuerSigningKey = jwk
    };
    
    var result = handler.ValidateToken(signatureJwt, validationParameters);
    
    // Validate signature claims
    var signatureClaims = result.Claims;
    if (signatureClaims["http_method"] != request.Method ||
        signatureClaims["http_path"] != request.Path ||
        signatureClaims["host"] != request.Host.Value)
    {
        return false;
    }
    
    // Validate timestamp (prevent replay, e.g., 5 minute window)
    var timestamp = long.Parse(signatureClaims["timestamp"]);
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    if (Math.Abs(now - timestamp) > 300)
    {
        return false;
    }
    
    return true;
}
```

**Security Benefits**:
- Token theft useless without private key
- Prevents man-in-the-middle attacks
- Prevents token replay (each request requires new signature)
- Binds token to specific client instance

**Implementation in Microsoft Identity Web**:
```csharp
// Location: MsAuth10AtPop.cs, AtPopOperation.cs

// Acquire PoP token
var result = await confidentialClient
    .AcquireTokenForClient(scopes)
    .WithAtPop(popPublicKey, jwkClaim) // Extension method
    .ExecuteAsync();
```

---

## Token Acquisition Flows

### Flow 1: Authorization Code Flow with PKCE (Web Apps)

**Entry Point**: `MicrosoftIdentityWebAppAuthenticationBuilderExtensions.cs`

**Step-by-Step**:

#### Step 1: User Navigates to Protected Resource
```csharp
// User accesses: https://app.contoso.com/profile
// No authentication cookie present
// Middleware detects unauthenticated request
```

#### Step 2: Redirect to Azure AD Authorization Endpoint
```csharp
// Event: OnRedirectToIdentityProvider
// Location: OpenIdConnectMiddlewareDiagnostics.cs

// Generate PKCE code verifier and challenge
string codeVerifier = GenerateRandomString(128); // Base64URL, 43-128 chars
string codeChallenge = Base64UrlEncode(SHA256(codeVerifier));
context.Properties.Items["code_verifier"] = codeVerifier; // Stored in session

// Build authorization request
var authorizationUrl = new StringBuilder();
authorizationUrl.Append($"{authority}/oauth2/v2.0/authorize?");
authorizationUrl.Append($"client_id={clientId}");
authorizationUrl.Append($"&response_type=code");
authorizationUrl.Append($"&redirect_uri={redirectUri}");
authorizationUrl.Append($"&response_mode=form_post"); // or query
authorizationUrl.Append($"&scope={scopes}"); // "openid profile User.Read"
authorizationUrl.Append($"&state={state}"); // CSRF token
authorizationUrl.Append($"&nonce={nonce}"); // Replay protection
authorizationUrl.Append($"&code_challenge={codeChallenge}");
authorizationUrl.Append($"&code_challenge_method=S256");
authorizationUrl.Append($"&prompt=select_account"); // Optional

// HTTP 302 redirect to Azure AD
context.Response.Redirect(authorizationUrl.ToString());
```

**Security Parameters**:
- `state`: CSRF token (validated on callback)
- `nonce`: Binds ID token to session (validated in ID token)
- `code_challenge`: PKCE challenge
- `code_challenge_method`: "S256" (SHA256 hash)

#### Step 3: User Authenticates at Azure AD
```
User presented with Azure AD login page:
- Email/username entry
- Password entry (or passwordless)
- MFA if required by conditional access
- Consent screen (if new scopes requested)
```

#### Step 4: Azure AD Redirects with Authorization Code
```http
POST https://app.contoso.com/signin-oidc HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=OAQABAAIAAADX8GCi6Js6SK82TsD2Pb7rFNHXf81...
&state={state}
&session_state=...
```

**Validation**:
```csharp
// Event: OnMessageReceived
// Validate state parameter (CSRF protection)
if (context.Request.Form["state"] != expectedState)
{
    throw new SecurityException("Invalid state parameter");
}
```

#### Step 5: Redeem Authorization Code for Tokens
```csharp
// Event: OnAuthorizationCodeReceived
// Location: TokenAcquisition.AddAccountToCacheFromAuthorizationCodeAsync

var authCode = context.Request.Form["code"];
var codeVerifier = context.Properties.Items["code_verifier"];

POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={clientId}
&scope={scopes}
&code={authCode}
&redirect_uri={redirectUri}
&grant_type=authorization_code
&code_verifier={codeVerifier}  // PKCE proof
&client_secret={secret} OR client_assertion={jwt}

// Response:
{
  "token_type": "Bearer",
  "scope": "User.Read openid profile",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI6...",
  "refresh_token": "0.AXoA1S...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtp..."
}
```

#### Step 6: Validate ID Token and Establish Session
```csharp
// Event: OnTokenValidated
// Validate ID token (automatic by middleware)
// Create authentication cookie
// Store tokens in cache

var claimsPrincipal = CreateClaimsPrincipal(idToken);
await context.HttpContext.SignInAsync(
    CookieAuthenticationDefaults.AuthenticationScheme,
    claimsPrincipal,
    authProperties);

// Store refresh token in server-side cache
await tokenCache.SaveAsync(refreshToken, userId);
```

**Result**: User logged in, session established, tokens cached

---

### Flow 2: Client Credentials Flow (Service-to-Service)

**Entry Point**: `TokenAcquisition.GetAccessTokenForAppAsync()`

**Use Case**: Daemon app calling Microsoft Graph without user

**Step-by-Step**:

#### Step 1: Build Confidential Client Application
```csharp
// Location: ConfidentialClientApplicationBuilderExtension.cs

IConfidentialClientApplication app = ConfidentialClientApplicationBuilder
    .Create(clientId)
    .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
    .WithClientSecret(clientSecret) // OR
    .WithCertificate(certificate)   // OR
    .WithClientAssertion(async () => await GetSignedAssertionAsync())
    .Build();
```

#### Step 2: Acquire Token for App
```csharp
// Request app-only token
var scopes = new[] { "https://graph.microsoft.com/.default" };

AuthenticationResult result = await app
    .AcquireTokenForClient(scopes)
    .ExecuteAsync();

// Token request:
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id={clientId}
&scope=https://graph.microsoft.com/.default
&client_secret={secret}  // OR client_assertion + client_assertion_type

// Response:
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI6..."
}
```

**Access Token Claims**:
```json
{
  "aud": "00000003-0000-0000-c000-000000000000", // Microsoft Graph
  "iss": "https://sts.windows.net/{tenantId}/",
  "iat": 1689582000,
  "nbf": 1689582000,
  "exp": 1689585600,
  "oid": "{servicePrincipalOid}",
  "roles": ["Mail.ReadWrite", "User.Read.All"], // Application permissions
  "sub": "{servicePrincipalOid}",
  "tid": "{tenantId}",
  "ver": "1.0"
}
```

**Key Differences from User Tokens**:
- No `scp` claim (uses `roles` instead)
- `oid` is service principal, not user
- Permissions are application permissions (admin-consented)

#### Step 3: Call Downstream API
```csharp
var accessToken = result.AccessToken;

var httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Authorization = 
    new AuthenticationHeaderValue("Bearer", accessToken);

var response = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users");
```

**Cache Behavior**:
```csharp
// Tokens cached by scope
// Cache key: {clientId}_{tenantId}_{scope}
// Automatic cache hit if token not expired
```

---

### Flow 3: On-Behalf-Of (OBO) Flow

**Entry Point**: `TokenAcquisition.GetAccessTokenForUserAsync()` in Web API context

**Scenario**: Web API receives user access token, needs to call Microsoft Graph on user's behalf

**Step-by-Step**:

#### Step 1: Web API Receives User Access Token
```csharp
// Client calls Web API
GET https://api.contoso.com/data
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6...

// Web API validates token
[Authorize]
[RequiredScope("access_as_user")]
public async Task<IActionResult> GetData()
{
    // User identity established
    var userId = User.FindFirst("oid").Value;
    
    // Need to call Graph API on behalf of user
    var graphToken = await tokenAcquisition.GetAccessTokenForUserAsync(
        new[] { "https://graph.microsoft.com/User.Read" });
}
```

#### Step 2: Acquire Token via OBO
```csharp
// Location: TokenAcquisition.GetAccessTokenForUserAsync (OBO variant)

// Extract incoming access token from HTTP context
var incomingToken = await context.HttpContext.GetTokenAsync("access_token");

POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&client_id={apiClientId}
&client_secret={apiSecret} OR client_assertion={jwt}
&assertion={incomingAccessToken}  // User's access token for this API
&scope=https://graph.microsoft.com/User.Read
&requested_token_use=on_behalf_of

// Response:
{
  "token_type": "Bearer",
  "scope": "User.Read",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI6...", // For Graph
  "refresh_token": "0.AXoA1S..." // For future OBO requests
}
```

**OBO Access Token Claims** (for Graph):
```json
{
  "aud": "00000003-0000-0000-c000-000000000000", // Microsoft Graph
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
  "oid": "{userOid}",  // Original user's OID
  "scp": "User.Read",  // Delegated permission
  "azp": "{apiClientId}",  // Authorized party (middle-tier API)
  "azpacr": "1",
  "sub": "{userSub}",
  "tid": "{tenantId}"
}
```

**Security Validations**:
1. Azure AD validates incoming token signature and lifetime
2. Validates that API (`azp`) is authorized to act on behalf of user
3. Validates user consented to requested scopes
4. Issues new token with middle-tier API as `azp` (authorized party)

#### Step 3: Cache OBO Token
```csharp
// Cache key includes:
// - User OID
// - Tenant ID
// - Scopes
// - Client ID (middle-tier API)

// This enables efficient subsequent OBO requests for same user + scopes
```

**Multi-Level OBO** (API A → API B → API C):
```
Client → API A (token1)
API A → API B (OBO token2 from token1)
API B → API C (OBO token3 from token2)

Each level performs OBO flow
Azure AD maintains full chain of trust
```

---

### Flow 4: Managed Identity Flow

**Entry Point**: `TokenAcquisition.ManagedIdentity.cs`

**Scenario**: Azure App Service app calling Azure Key Vault

**Step-by-Step**:

#### Step 1: Configure Managed Identity
```bash
# Enable system-assigned managed identity on App Service
az webapp identity assign --name myapp --resource-group mygroup

# OR use user-assigned managed identity
az identity create --name myidentity --resource-group mygroup
az webapp identity assign --name myapp --resource-group mygroup \
    --identities /subscriptions/{sub}/resourceGroups/mygroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myidentity
```

#### Step 2: Application Requests Token
```csharp
// No configuration needed in app code
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(options =>
    {
        options.IsForManagedIdentity = true;
        // No client secret or certificate!
    });

// Acquire token
var token = await tokenAcquisition.GetAccessTokenForAppAsync(
    "https://vault.azure.net/.default");
```

#### Step 3: Azure Instance Metadata Service (IMDS) Call
```csharp
// Location: TokenAcquisition.ManagedIdentity.cs
// Internal MSAL.NET call to IMDS

GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01
    &resource=https://vault.azure.net
    &client_id={managedIdentityClientId} // If user-assigned
Metadata: true

// Response from IMDS:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng...",
  "client_id": "{managedIdentityClientId}",
  "expires_in": "86399",
  "expires_on": "1689668400",
  "ext_expires_in": "86399",
  "not_before": "1689582000",
  "resource": "https://vault.azure.net",
  "token_type": "Bearer"
}
```

**Access Token Claims**:
```json
{
  "aud": "https://vault.azure.net",
  "iss": "https://sts.windows.net/{tenantId}/",
  "oid": "{managedIdentityPrincipalId}",
  "sub": "{managedIdentityPrincipalId}",
  "tid": "{tenantId}",
  "xms_mirid": "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/myapp"
}
```

#### Step 4: Use Token to Access Resource
```csharp
var secretClient = new SecretClient(
    new Uri("https://myvault.vault.azure.net"),
    new DefaultAzureCredential()); // Uses managed identity automatically

var secret = await secretClient.GetSecretAsync("my-secret");
```

**Security Benefits**:
- Zero secrets in application code or configuration
- Automatic credential rotation (Azure-managed)
- Cannot exfiltrate credentials (tied to Azure resource)
- IMDS only accessible from within Azure resource (169.254.x.x network)

---

## Token Validation and Verification

### JWT Signature Validation

**Algorithm Support**:
```csharp
// Location: JwtBearerMiddlewareDiagnostics.cs

// Allowed algorithms (Azure AD uses these):
AllowedAlgorithms = new[] {
    "RS256", "RS384", "RS512", // RSA
    "ES256", "ES384", "ES512"  // ECDSA
};

// Forbidden algorithms:
ForbiddenAlgorithms = new[] {
    "none", // Unsigned tokens
    "HS256", "HS384", "HS512" // Symmetric (not used by Azure AD)
};
```

**Signature Validation Process**:
```csharp
// 1. Download Azure AD public keys (JWKS)
var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    new OpenIdConnectConfigurationRetriever(),
    new HttpDocumentRetriever());

var oidcConfig = await configManager.GetConfigurationAsync();
var signingKeys = oidcConfig.SigningKeys; // Collection of JsonWebKey

// 2. Extract 'kid' from token header
var handler = new JwtSecurityTokenHandler();
var jwtToken = handler.ReadJwtToken(tokenString);
var kid = jwtToken.Header.Kid;

// 3. Find matching key
var signingKey = signingKeys.FirstOrDefault(k => k.KeyId == kid);
if (signingKey == null)
{
    // Key rotation might have occurred, refresh OIDC config
    configManager.RequestRefresh();
    oidcConfig = await configManager.GetConfigurationAsync();
    signingKey = oidcConfig.SigningKeys.FirstOrDefault(k => k.KeyId == kid);
}

// 4. Validate signature
var validationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = signingKey,
    ValidateIssuer = true,
    ValidIssuer = "https://login.microsoftonline.com/{tenant}/v2.0",
    ValidateAudience = true,
    ValidAudience = "{clientId}",
    ValidateLifetime = true,
    ClockSkew = TimeSpan.FromMinutes(5)
};

ClaimsPrincipal principal = handler.ValidateToken(
    tokenString,
    validationParameters,
    out SecurityToken validatedToken);
```

**Key Rotation Handling**:
```
Azure AD rotates signing keys every 6 weeks
Library caches OIDC configuration for 24 hours
On validation failure with cached keys:
  1. Refresh OIDC configuration
  2. Retry validation with new keys
  3. If still fails, reject token
```

### Issuer Validation

**Multi-Tenant Issuer Validation**:
```csharp
// Location: MicrosoftIdentityIssuerValidatorFactory.cs

public string Validate(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
{
    // Extract tenant ID from issuer
    // V2 format: https://login.microsoftonline.com/{tenantId}/v2.0
    // V1 format: https://sts.windows.net/{tenantId}/
    
    var match = Regex.Match(issuer, @"https://sts\.windows\.net/(.*?)/|https://login\.microsoftonline\.com/(.*?)/v2\.0");
    if (!match.Success)
    {
        throw new SecurityTokenInvalidIssuerException($"Invalid issuer format: {issuer}");
    }
    
    var tenantId = match.Groups[1].Value ?? match.Groups[2].Value;
    
    // Validate against allowlist
    if (!IsAllowedTenant(tenantId))
    {
        throw new SecurityTokenInvalidIssuerException($"Tenant {tenantId} not authorized");
    }
    
    return issuer;
}
```

**Common Configurations**:

| Scenario | Issuer Configuration |
|----------|---------------------|
| Single tenant | `https://login.microsoftonline.com/{specificTenantId}/v2.0` |
| Multi-tenant (any Azure AD) | Custom validator with tenant allowlist |
| Azure AD B2C | `https://{tenant}.b2clogin.com/{tenantId}/v2.0` |

### Audience Validation

**Web API Audience Validation**:
```csharp
// Valid audience values for API
ValidAudiences = new[] {
    "{clientId}",              // Application client ID
    "api://{clientId}",        // App ID URI format
    "https://myapi.contoso.com" // Custom App ID URI
};

// Token must have aud claim matching one of these
```

**Graph API Audience**:
```json
{
  "aud": "00000003-0000-0000-c000-000000000000" // Microsoft Graph
}
```

### Lifetime Validation

**Claims Checked**:
```csharp
var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
var exp = long.Parse(token.Claims.First(c => c.Type == "exp").Value);
var nbf = long.Parse(token.Claims.First(c => c.Type == "nbf").Value);

// Expiration check
if (now > exp + ClockSkew.TotalSeconds)
{
    throw new SecurityTokenExpiredException("Token expired");
}

// Not-before check
if (now < nbf - ClockSkew.TotalSeconds)
{
    throw new SecurityTokenNotYetValidException("Token not yet valid");
}
```

**Clock Skew**: Default 5 minutes (allows for clock drift between client/server)

---

## Token Caching Strategies

### Cache Key Structure

**User Token Cache Key**:
```
Format: {clientId}_{oid}_{tenantId}_TokenCache

Example: 
1234-5678-9abc-def0_a1b2c3d4-e5f6-7890-abcd-ef1234567890_9988-7766-5544-3322_TokenCache
```

**App Token Cache Key**:
```
Format: {clientId}_{tenantId}_AppTokenCache

Example:
1234-5678-9abc-def0_9988-7766-5544-3322_AppTokenCache
```

**OBO Token Cache Key**:
```
Format: {clientId}_{oid}_{tenantId}_{assertion_hash}_TokenCache

Includes hash of incoming access token to differentiate OBO chains
```

### Distributed Cache Implementation

**Redis Example**:
```csharp
// Startup.cs
services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = "localhost:6379";
    options.InstanceName = "MsalTokenCache:";
});

services.AddMicrosoftIdentityWebApiAuthentication(configuration)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddDistributedTokenCaches();

// Behind the scenes:
// Location: MsalDistributedTokenCacheAdapter.cs

public async Task SaveAsync(byte[] cacheData, string cacheKey)
{
    var options = new DistributedCacheEntryOptions
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(90), // Refresh token lifetime
        SlidingExpiration = TimeSpan.FromDays(14) // Inactive user cleanup
    };
    
    await distributedCache.SetAsync(
        cacheKey,
        cacheData, // MSAL-serialized cache (encrypted by MSAL)
        options);
}
```

**Cache Serialization**:
```
MSAL serializes token cache to JSON:
{
  "AccessToken": {
    "HomeAccountId": "...",
    "Environment": "login.microsoftonline.com",
    "CredentialType": "AccessToken",
    "ClientId": "...",
    "Secret": "eyJ0eXAiOiJKV1QiLCJub25jZSI6...",
    "ExpiresOn": "1689585600",
    "CachedAt": "1689582000",
    "Target": "User.Read Mail.Send"
  },
  "RefreshToken": {
    "HomeAccountId": "...",
    "Environment": "login.microsoftonline.com",
    "CredentialType": "RefreshToken",
    "ClientId": "...",
    "Secret": "0.AXoA1S...",
    "Target": "User.Read Mail.Send offline_access"
  },
  "IdToken": { ... },
  "Account": { ... }
}

Microsoft Identity Web encrypts this JSON before storing in distributed cache
```

### Cache Partitioning

**User Isolation**:
- Each user has separate cache entry (keyed by OID + TenantID)
- Prevents user A from accessing user B's tokens
- Enables multi-user support in same application instance

**Multi-Tenant Isolation**:
- Tenant ID included in cache key
- Same user in different tenants has separate cache entries
- Prevents cross-tenant token leakage

### Cache Eviction Strategies

**Expiration-Based**:
```csharp
// Sliding expiration: Evict if not accessed for 14 days
// Absolute expiration: Evict after 90 days (refresh token lifetime)

var cacheOptions = new DistributedCacheEntryOptions
{
    SlidingExpiration = TimeSpan.FromDays(14),
    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(90)
};
```

**Event-Based**:
- User password change → Revoke all refresh tokens → Cache invalidated
- Admin token revocation → MSAL detects on next use → Cache cleared
- Logout → Explicit cache clear for user

---

## Token Security Mechanisms

### Secure Token Storage

**Web Apps** (Server-Side Storage):
```csharp
// ✅ GOOD: Server-side distributed cache
.AddDistributedTokenCaches();

// ✅ GOOD: Server-side session
.AddSessionTokenCaches();

// ❌ BAD: Do not send tokens to browser
// Do not store in:
// - LocalStorage
// - SessionStorage
// - Cookies (unless encrypted and HttpOnly)
```

**Native/Mobile Apps**:
```csharp
// Platform-specific secure storage
// iOS: Keychain
// Android: Keystore
// Windows: DPAPI

// MSAL handles this automatically for native apps
```

### Token Encryption

**At Rest**:
- Distributed cache: Encrypted by cache provider (Redis TLS, SQL TDE)
- Session cache: ASP.NET Core Data Protection API
- Native apps: OS-provided secure storage

**In Transit**:
- TLS 1.2+ required for all HTTP requests
- Token acquisition: HTTPS only
- API calls: Bearer token over HTTPS

### Token Binding (PoP)

**See PoP Token section above for detailed implementation**

**Benefits**:
- Prevents bearer token theft attacks
- Cryptographic proof required for each request
- Meets high-security compliance (finance, healthcare)

---

## Advanced Token Scenarios

### Incremental Consent

**Scenario**: Request additional scopes after initial login

**Implementation**:
```csharp
// Initial login: User.Read scope
// Later, app needs Mail.Send scope

try
{
    var token = await tokenAcquisition.GetAccessTokenForUserAsync(
        new[] { "Mail.Send" }); // New scope
}
catch (MicrosoftIdentityWebChallengeUserException ex)
{
    // User has not consented to Mail.Send
    // Redirect to Azure AD for consent
    
    context.Response.Challenge(
        new AuthenticationProperties
        {
            RedirectUri = "/api/sendmail"
        },
        OpenIdConnectDefaults.AuthenticationScheme);
}

// After consent:
// Authorization code flow executes again
// New token with both User.Read and Mail.Send scopes
```

**User Experience**:
- User redirected to Azure AD
- Consent screen shows only new scopes
- After consent, returned to application
- New token cached with expanded scopes

### Conditional Access Compliance

**Scenario**: API requires step-up authentication (e.g., MFA)

**Claims Challenge**:
```csharp
// API returns claims challenge
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", error="insufficient_claims", claims="eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZSwgInZhbHVlIjoiMTYwNDEwNjY1MCJ9fX0="

// Decoded claims:
{
  "access_token": {
    "nbf": {
      "essential": true,
      "value": "1604106650"
    }
  }
}

// Client handles claims challenge:
// Location: MicrosoftIdentityConsentAndConditionalAccessHandler.cs

catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
{
    // Extract claims from WWW-Authenticate header
    var claims = ExtractClaimsFromWwwAuthenticateHeader(ex.Headers);
    
    // Redirect to Azure AD with claims parameter
    context.Response.Challenge(
        new AuthenticationProperties
        {
            Parameters = { { "claims", claims } }
        });
}

// User performs step-up auth (e.g., MFA)
// New token issued with required claims
```

### App Roles and Scopes

**Delegated Permissions (Scopes)**:
```json
// Manifest:
{
  "oauth2PermissionScopes": [
    {
      "id": "guid",
      "value": "access_as_user",
      "type": "User",
      "adminConsentDisplayName": "Access API as user",
      "adminConsentDescription": "Allows the app to access the API on behalf of the signed-in user"
    }
  ]
}

// Token:
{
  "scp": "access_as_user"
}

// Validation:
[RequiredScope("access_as_user")]
```

**Application Permissions (App Roles)**:
```json
// Manifest:
{
  "appRoles": [
    {
      "id": "guid",
      "value": "Data.Read.All",
      "allowedMemberTypes": ["Application"],
      "displayName": "Read all data",
      "description": "Allows the app to read all data"
    }
  ]
}

// Token:
{
  "roles": ["Data.Read.All"]
}

// Validation:
[RequiredScopeOrAppPermission(AcceptedAppPermission = new[] { "Data.Read.All" })]
```

---

## Token Lifecycle Management

### Token Expiration Handling

**Automatic Refresh** (Web Apps):
```csharp
// MSAL automatically uses refresh token when access token expires
var token = await tokenAcquisition.GetAccessTokenForUserAsync(scopes);

// Internal logic:
// 1. Check cache for access token
// 2. If expired, check for refresh token
// 3. If refresh token exists, silently acquire new access token
// 4. Update cache with new tokens
// 5. Return new access token
```

**Manual Refresh** (Rare):
```csharp
var result = await confidentialClient
    .AcquireTokenSilent(scopes, account)
    .WithForceRefresh(true) // Force refresh even if cached token valid
    .ExecuteAsync();
```

### Token Revocation

**User-Initiated Revocation**:
```csharp
// Logout and revoke tokens
await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

// Clear token cache
await tokenCache.ClearAsync(userId);

// Optional: Call Azure AD revocation endpoint (revokes refresh token)
await confidentialClient.RemoveAsync(account);
```

**Admin-Initiated Revocation**:
```powershell
# PowerShell: Revoke all tokens for user
Revoke-AzureADUserAllRefreshToken -ObjectId {userOid}
```

**Automatic Revocation Triggers**:
- Password change
- User disabled/deleted
- Conditional access policy change
- Admin-forced sign-out

### Certificate Rotation

**Zero-Downtime Rotation**:
```csharp
// Location: ICertificatesObserver interface

public interface ICertificatesObserver
{
    void OnCertificateUpdated(X509Certificate2 certificate);
}

// Implementation:
public class CertificateRotationHandler : ICertificatesObserver
{
    private readonly IConfidentialClientApplication _app;
    
    public void OnCertificateUpdated(X509Certificate2 newCertificate)
    {
        // Update MSAL application with new certificate
        // Old cert still works during overlap period
        // New tokens signed with new cert
        
        _app = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithCertificate(newCertificate)
            .Build();
    }
}

// Registration:
services.AddSingleton<ICertificatesObserver, CertificateRotationHandler>();
```

**Best Practice**:
1. Add new certificate to Azure AD app registration
2. Deploy new certificate to application (overlap period)
3. Application starts using new cert for new token requests
4. Wait for all old tokens to expire (1 hour)
5. Remove old certificate from Azure AD

---

## Conclusion

Microsoft Identity Web provides comprehensive token management across all OAuth 2.0/OIDC scenarios:

1. **Multiple Token Types**: ID, Access, Refresh, PoP, Authorization Codes
2. **Secure Flows**: Authorization Code + PKCE, Client Credentials, OBO, Managed Identity
3. **Robust Validation**: Signature, issuer, audience, lifetime checks
4. **Scalable Caching**: Distributed, partitioned, encrypted token storage
5. **Advanced Security**: PoP tokens, certificate rotation, conditional access
6. **Production-Ready**: Automatic refresh, revocation, multi-tenant support

This documentation provides the technical depth needed to understand, implement, and troubleshoot token-based authentication in enterprise applications using Microsoft Identity Web.

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-22  
**Intended Audience**: Security Engineers, Senior Software Engineers, Solution Architects
