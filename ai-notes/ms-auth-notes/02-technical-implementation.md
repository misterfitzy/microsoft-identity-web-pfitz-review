# MSAuth 1.0 Technical Implementation Guide

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Code Walkthrough](#code-walkthrough)
4. [Integration Points](#integration-points)
5. [Configuration Options](#configuration-options)
6. [Testing Strategies](#testing-strategies)
7. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│        Microsoft.Identity.Web.TokenAcquisition Package           │
└─────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                         Public API Layer                           │
├────────────────────────────────────────────────────────────────────┤
│  TokenAcquisition.cs                                               │
│    ├─ GetAuthenticationResultForAppAsync()                         │
│    └─ Configures: PopPublicKey, PopClaim, SendX5C                  │
└────────────────┬───────────────────────────────────────────────────┘
                 │
                 ├──────────────────────────────────────────┐
                 │                                          │
┌────────────────▼────────────────┐      ┌─────────────────▼─────────────┐
│  MsAuth10AtPop.cs               │      │  AtPopOperation.cs            │
│  (Extension Methods)            │      │  (Operation Implementation)    │
├─────────────────────────────────┤      ├───────────────────────────────┤
│  + WithAtPop()                  │      │  + KeyId: string              │
│    - Validates parameters       │      │  + AccessTokenType: "pop"     │
│    - Creates AtPopOperation     │      │  + TelemetryTokenType: 4      │
│    - Attaches to MSAL builder   │      │  + GetTokenRequestParams()    │
└─────────────────────────────────┘      │    - req_cnf (base64url)      │
                                         │    - token_type: "pop"        │
                                         └───────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                    MSAL.NET Integration Layer                       │
├────────────────────────────────────────────────────────────────────┤
│  Microsoft.Identity.Client                                         │
│    ├─ IAuthenticationOperation interface                           │
│    ├─ MsalAuthenticationExtension                                  │
│    └─ AcquireTokenForClientParameterBuilder                        │
└────────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. MsAuth10AtPop.cs

**Location:** `src/Microsoft.Identity.Web.TokenAcquisition/MsAuth10AtPop.cs`

**Purpose:** Provides extension method to enable MSAuth 1.0 AT-POP on MSAL token acquisition builders.

#### Complete Source Code

```csharp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;

namespace Microsoft.Identity.Web
{
    internal static class MsAuth10AtPop
    {
        /// <summary>
        /// Extension method to configure MSAuth 1.0 AT-POP on token acquisition.
        /// </summary>
        /// <param name="builder">MSAL token acquisition builder</param>
        /// <param name="popPublicKey">Public key identifier (kid) for PoP binding</param>
        /// <param name="jwkClaim">JWK (JSON Web Key) as JSON string</param>
        /// <returns>Builder with AT-POP configured</returns>
        internal static AcquireTokenForClientParameterBuilder WithAtPop(
            this AcquireTokenForClientParameterBuilder builder,
            string popPublicKey,
            string jwkClaim)
        {
            // Validation: Ensure popPublicKey is not null or whitespace
            _ = Throws.IfNullOrWhitespace(popPublicKey);
            
            // Validation: Ensure jwkClaim is not null or whitespace
            _ = Throws.IfNullOrWhitespace(jwkClaim);

            // Create the AT-POP operation with key ID and JWK
            AtPopOperation op = new AtPopOperation(popPublicKey, jwkClaim);
            
            // Attach the operation to the builder via MSAL's authentication extension
            builder.WithAuthenticationExtension(new MsalAuthenticationExtension()
            {
                AuthenticationOperation = op
            });
            
            return builder;
        }
    }
}
```

#### Key Implementation Details

**1. Extension Method Pattern**

```csharp
internal static AcquireTokenForClientParameterBuilder WithAtPop(
    this AcquireTokenForClientParameterBuilder builder, ...)
```

- Uses C# extension method syntax (`this` keyword)
- Allows fluent API: `builder.AcquireTokenForClient(...).WithAtPop(...).ExecuteAsync()`
- Operates on `AcquireTokenForClientParameterBuilder` from MSAL.NET

**2. Parameter Validation**

```csharp
_ = Throws.IfNullOrWhitespace(popPublicKey);
_ = Throws.IfNullOrWhitespace(jwkClaim);
```

- Uses custom `Throws` utility class for consistent error handling
- Throws `ArgumentException` if `popPublicKey` is null/empty/whitespace
- Throws `ArgumentNullException` if `jwkClaim` is null

**3. Operation Creation and Registration**

```csharp
AtPopOperation op = new AtPopOperation(popPublicKey, jwkClaim);
builder.WithAuthenticationExtension(new MsalAuthenticationExtension()
{
    AuthenticationOperation = op
});
```

- Creates `AtPopOperation` instance with key parameters
- Wraps in `MsalAuthenticationExtension` container
- Registers with MSAL builder via `WithAuthenticationExtension()`

---

### 2. AtPopOperation.cs

**Location:** `src/Microsoft.Identity.Web.TokenAcquisition/AtPopOperation.cs`

**Purpose:** Implements the `IAuthenticationOperation` interface to customize MSAL token requests for MSAuth 1.0 AT-POP.

#### Complete Source Code

```csharp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.Identity.Client.AuthScheme;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Identity.Web
{
    /// <summary>
    /// Implements MSAL IAuthenticationOperation for MSAuth 1.0 AT-POP.
    /// Customizes token requests to include req_cnf and token_type=pop.
    /// </summary>
    internal class AtPopOperation : IAuthenticationOperation
    {
        private readonly string _reqCnf;

        /// <summary>
        /// Constructor for AT-POP operation.
        /// </summary>
        /// <param name="keyId">Key identifier (kid) for the PoP key</param>
        /// <param name="reqCnf">JWK claim as JSON string</param>
        public AtPopOperation(string keyId, string reqCnf)
        {
            KeyId = keyId;
            _reqCnf = reqCnf;
        }

        /// <summary>
        /// Telemetry token type constant (4 = PoP token).
        /// As per TelemetryTokenTypeConstants in MSAL.
        /// </summary>
        public int TelemetryTokenType => 4;

        /// <summary>
        /// Authorization header prefix.
        /// Despite being PoP, uses "Bearer" for compatibility.
        /// </summary>
        public string AuthorizationHeaderPrefix => "Bearer";

        /// <summary>
        /// Key identifier for the PoP key.
        /// </summary>
        public string KeyId { get; }

        /// <summary>
        /// Expected token_type in the token response.
        /// eSTS returns token_type=pop and MSAL needs to validate this.
        /// </summary>
        public string AccessTokenType => "pop";

        /// <summary>
        /// No-op method. Result formatting is handled by caller.
        /// Adding the Signed HTTP Request (SHR) is done by the caller if needed.
        /// </summary>
        public void FormatResult(AuthenticationResult authenticationResult)
        {
            // No operation - result formatting handled elsewhere
        }

        /// <summary>
        /// Provides additional parameters to include in the token request.
        /// </summary>
        /// <returns>Dictionary with req_cnf and token_type parameters</returns>
        public IReadOnlyDictionary<string, string> GetTokenRequestParams()
        {
            return new Dictionary<string, string>()
            {
                // Base64url-encode the JWK for transport
                {"req_cnf", Base64UrlEncoder.Encode(_reqCnf) },
                
                // Specify token type as "pop"
                {"token_type", "pop" }
            };
        }
    }
}
```

#### Interface Implementation: `IAuthenticationOperation`

**Interface Definition (from MSAL.NET):**

```csharp
namespace Microsoft.Identity.Client
{
    public interface IAuthenticationOperation
    {
        // Telemetry code for this token type
        int TelemetryTokenType { get; }
        
        // Prefix for Authorization header (e.g., "Bearer", "PoP")
        string AuthorizationHeaderPrefix { get; }
        
        // Unique identifier for the key
        string KeyId { get; }
        
        // Expected token_type in response
        string AccessTokenType { get; }
        
        // Customize the AuthenticationResult after acquisition
        void FormatResult(AuthenticationResult authenticationResult);
        
        // Additional parameters to add to token request
        IReadOnlyDictionary<string, string> GetTokenRequestParams();
    }
}
```

#### Property and Method Analysis

**1. TelemetryTokenType**

```csharp
public int TelemetryTokenType => 4;
```

- **Purpose:** Tracks token type in telemetry/logging
- **Value:** `4` = PoP token (from `TelemetryTokenTypeConstants` in MSAL)
- **Usage:** MSAL uses this for metrics and diagnostics

| Telemetry Code | Token Type |
|---------------|------------|
| 1 | Bearer |
| 2 | PoP (generic) |
| 3 | SSH Certificate |
| **4** | **AT-POP (MSAuth 1.0)** |

**2. AuthorizationHeaderPrefix**

```csharp
public string AuthorizationHeaderPrefix => "Bearer";
```

- **Surprising but intentional:** Returns "Bearer" despite being PoP token
- **Reason:** Compatibility with existing HTTP infrastructure
- **Effect:** Token sent as `Authorization: Bearer {token}`
- **Security:** Token is still cryptographically bound; header prefix doesn't affect PoP security

**3. KeyId**

```csharp
public string KeyId { get; }
```

- **Purpose:** Unique identifier for the PoP key
- **Source:** Provided in constructor (`popPublicKey` parameter)
- **Usage:** Included in `cnf` claim of issued token
- **Format:** Typically a JWK thumbprint or custom identifier

**4. AccessTokenType**

```csharp
public string AccessTokenType => "pop";
```

- **Purpose:** Declares expected token_type in Azure AD's response
- **Validation:** MSAL checks response has `token_type=pop`
- **Effect:** Ensures PoP token was issued (not bearer token)

**5. FormatResult()**

```csharp
public void FormatResult(AuthenticationResult authenticationResult)
{
    // No-op
}
```

- **Purpose:** Hook to modify `AuthenticationResult` after token acquisition
- **Implementation:** Empty (no-op) for MSAuth 1.0 AT-POP
- **Reason:** Result formatting handled by caller; SHR (Signed HTTP Request) added separately if needed

**6. GetTokenRequestParams()**

```csharp
public IReadOnlyDictionary<string, string> GetTokenRequestParams()
{
    return new Dictionary<string, string>()
    {
        {"req_cnf", Base64UrlEncoder.Encode(_reqCnf) },
        {"token_type", "pop" }
    };
}
```

- **Purpose:** Injects MSAuth 1.0-specific parameters into token request
- **Parameters:**
  - `req_cnf`: Base64url-encoded JWK (public key)
  - `token_type`: Literal string "pop"
- **Encoding:** Uses `Base64UrlEncoder.Encode()` from `Microsoft.IdentityModel.Tokens`

**Base64URL Encoding:**
```
Original JWK: {"kty":"RSA","e":"AQAB",...}
Base64URL:    eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsLi4ufQ
```

---

### 3. TokenAcquisition.cs Integration

**Location:** `src/Microsoft.Identity.Web.TokenAcquisition/TokenAcquisition.cs`

**Relevant Method:** `GetAuthenticationResultForAppAsync()`

#### Integration Code

```csharp
// Inside GetAuthenticationResultForAppAsync() method

// ... (earlier setup code) ...

// Check if PoP is configured
if (!string.IsNullOrEmpty(tokenAcquisitionOptions.PopPublicKey))
{
    _logger.LogInformation("Regular SHR POP with server nonce configured");

    if (string.IsNullOrEmpty(tokenAcquisitionOptions.PopClaim))
    {
        // ===== Mode 1: Regular PoP (not MSAuth 1.0) =====
        builder.WithProofOfPosessionKeyId(tokenAcquisitionOptions.PopPublicKey, "pop");
        builder.OnBeforeTokenRequest((data) =>
        {
            data.BodyParameters.Add("req_cnf", tokenAcquisitionOptions.PopPublicKey);
            data.BodyParameters.Add("token_type", "pop");
            return Task.CompletedTask;
        });
    }
    else
    {
        // ===== Mode 2: MSAuth 1.0 AT-POP =====
        
        if (mergedOptions.SendX5C)
        {
            // Recommended: SN/I (Subject Name / Issuer) mode
            _logger.LogInformation("MSAuth POP configured with SN/I");
        }
        else
        {
            // Deprecated: Pinned certificate mode
            _logger.LogWarning(
                "MSAuth POP configured with pinned certificate. " +
                "This configuration is being deprecated.");
        }

        // Apply MSAuth 1.0 AT-POP via extension method
        builder.WithAtPop(
           tokenAcquisitionOptions.PopPublicKey!,
           tokenAcquisitionOptions.PopClaim!);
    }
}

// Execute token acquisition
var result = await builder.ExecuteAsync(
    tokenAcquisitionOptions?.CancellationToken ?? CancellationToken.None);
```

#### Decision Logic

**Condition Tree:**

```
PopPublicKey != null/empty?
├─ NO ──► Regular bearer token (no PoP)
└─ YES ──► PopClaim != null/empty?
           ├─ NO ──► Regular PoP (manual req_cnf/token_type)
           └─ YES ──► MSAuth 1.0 AT-POP
                      └─ SendX5C?
                         ├─ YES ──► SN/I mode (recommended)
                         └─ NO ──► Pinned cert mode (deprecated)
```

**Configuration Properties:**

| Property | Type | Purpose | MSAuth 1.0 Required |
|----------|------|---------|---------------------|
| `PopPublicKey` | `string?` | Key identifier | ✅ Yes |
| `PopClaim` | `string?` | JWK JSON | ✅ Yes |
| `SendX5C` | `bool` | Use SN/I vs. pinned cert | ❌ No (affects mode) |

---

## Code Walkthrough

### End-to-End Flow

#### Step 1: Configure PoP Options

```csharp
var tokenAcquisitionOptions = new TokenAcquisitionOptions
{
    PopPublicKey = "key-abc-123",  // Key identifier
    PopClaim = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"0vx...\"}", // JWK JSON
};
```

#### Step 2: Create MSAL Application

```csharp
var app = ConfidentialClientApplicationBuilder
    .Create(clientId)
    .WithCertificate(certificate)
    .WithExperimentalFeatures()  // Required for custom auth operations
    .Build();
```

#### Step 3: Acquire Token with MSAuth 1.0

```csharp
var result = await app.AcquireTokenForClient(scopes)
    .WithAtPop(
        tokenAcquisitionOptions.PopPublicKey,
        tokenAcquisitionOptions.PopClaim)
    .ExecuteAsync();
```

**Internal Flow:**

1. `WithAtPop()` validates parameters
2. Creates `AtPopOperation(keyId, jwkClaim)`
3. Wraps in `MsalAuthenticationExtension`
4. MSAL calls `GetTokenRequestParams()` before sending request
5. Request includes `req_cnf` and `token_type=pop`
6. Azure AD binds token to key, returns PoP token
7. MSAL validates `token_type=pop` in response
8. Returns `AuthenticationResult` with PoP access token

#### Step 4: Use PoP Token

```csharp
var httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Authorization = 
    new AuthenticationHeaderValue("Bearer", result.AccessToken);

var response = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");
```

---

## Integration Points

### MSAL.NET Integration

**Package:** `Microsoft.Identity.Client` (MSAL.NET)

**Key Interfaces:**

1. **`IAuthenticationOperation`**
   - Contract for custom authentication schemes
   - Implemented by `AtPopOperation`

2. **`MsalAuthenticationExtension`**
   - Container for `IAuthenticationOperation`
   - Registered via `WithAuthenticationExtension()`

3. **`AcquireTokenForClientParameterBuilder`**
   - Fluent API for token acquisition
   - Extended by `WithAtPop()`

**MSAL Processing Flow:**

```
AcquireTokenForClient(scopes)
  └─► WithAtPop(key, jwk)
       └─► WithAuthenticationExtension(extension)
            └─► ExecuteAsync()
                 ├─► GetTokenRequestParams()
                 │    └─► Add req_cnf, token_type to request
                 ├─► Send HTTP POST to Azure AD
                 ├─► Validate response token_type == "pop"
                 └─► Return AuthenticationResult
```

---

### TokenAcquisitionOptions Properties

**Source:** `Microsoft.Identity.Abstractions.AcquireTokenOptions` (base class)

```csharp
public class AcquireTokenOptions
{
    // MSAuth 1.0 AT-POP properties
    public string? PopPublicKey { get; set; }
    public string? PopClaim { get; set; }
    
    // Other PoP property
    public PoPAuthenticationConfiguration? PoPConfiguration { get; set; }
    
    // Standard OAuth properties
    public string? Tenant { get; set; }
    public string? Claims { get; set; }
    public bool ForceRefresh { get; set; }
    public Guid? CorrelationId { get; set; }
    // ... (more properties)
}
```

**Property Usage:**

- **`PopPublicKey`**: Key identifier (kid), sent as-is in token request
- **`PopClaim`**: JWK JSON string, base64url-encoded to create `req_cnf`
- **Relationship:** Both must be set for MSAuth 1.0; if only `PopPublicKey` is set, falls back to regular PoP

---

## Configuration Options

### Configuration Pattern

```csharp
services.AddMicrosoftIdentityWebAppAuthentication(configuration)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddInMemoryTokenCaches();

// Later, when calling API:
var token = await tokenAcquisition.GetAccessTokenForAppAsync(
    scopes,
    authenticationScheme: null,
    tokenAcquisitionOptions: new TokenAcquisitionOptions
    {
        PopPublicKey = GetKeyIdentifier(),
        PopClaim = GetJwkClaim(),
    });
```

### Key Generation Example

```csharp
using System.Security.Cryptography;
using System.Text.Json;

public (string KeyId, string JwkClaim) GeneratePopKey()
{
    // Generate RSA key pair
    using var rsa = RSA.Create(2048);
    var parameters = rsa.ExportParameters(includePrivateParameters: false);
    
    // Create JWK
    var jwk = new
    {
        kty = "RSA",
        e = Base64UrlEncoder.Encode(parameters.Exponent),
        n = Base64UrlEncoder.Encode(parameters.Modulus),
        alg = "RS256",
        kid = Guid.NewGuid().ToString()
    };
    
    string jwkJson = JsonSerializer.Serialize(jwk);
    string keyId = jwk.kid;
    
    // Store private key securely for later proof generation
    StorePrivateKey(rsa.ExportParameters(includePrivateParameters: true));
    
    return (keyId, jwkJson);
}
```

---

## Testing Strategies

### Unit Tests

**Location:** `tests/Microsoft.Identity.Web.Test/MsAuth10AtPopTests.cs`

#### Test 1: Successful Token Acquisition

```csharp
[Fact]
public async Task MsAuth10AtPop_WithAtPop_ShouldPopulateBuilderWithProofOfPosessionKeyIdAndOnBeforeTokenRequestTestAsync()
{
    // Arrange
    using MockHttpClientFactory mockHttpClientFactory = new MockHttpClientFactory();
    using var httpTokenRequest = MockHttpCreator.CreateClientCredentialTokenHandler(tokenType: "pop");
    mockHttpClientFactory.AddMockHandler(httpTokenRequest);

    var app = ConfidentialClientApplicationBuilder.Create(TestConstants.ClientId)
                    .WithExperimentalFeatures()
                    .WithCertificate(certificateDescription.Certificate)
                    .WithHttpClientFactory(mockHttpClientFactory)
                    .Build();

    var popPublicKey = "pop_key";
    var jwkClaim = "jwk_claim";

    // Act
    AuthenticationResult result = await app.AcquireTokenForClient(new[] { TestConstants.Scopes })
        .WithAtPop(popPublicKey, jwkClaim)
        .ExecuteAsync();

    // Assert
    httpTokenRequest.ActualRequestPostData.TryGetValue("req_cnf", out string? reqCnf);
    Assert.Equal(Base64UrlEncoder.Encode(jwkClaim), reqCnf);

    httpTokenRequest.ActualRequestPostData.TryGetValue("token_type", out string? tokenType);
    Assert.Equal("pop", tokenType);
}
```

**Verification Points:**
1. ✅ `req_cnf` parameter is base64url-encoded JWK
2. ✅ `token_type` parameter is "pop"
3. ✅ `client_assertion` is present (client authentication)

#### Test 2: Null PopPublicKey Validation

```csharp
[Fact]
public void MsAuth10AtPop_ThrowsWithNullPopKeyTest()
{
    // Arrange
    IConfidentialClientApplication app = CreateBuilder();
    var jwkClaim = "jwk_claim";

    // Act & Assert
    Assert.Throws<ArgumentException>(() => MsAuth10AtPop.WithAtPop(
        app.AcquireTokenForClient([TestConstants.Scopes]),
        string.Empty,  // Invalid: empty string
        jwkClaim));
}
```

#### Test 3: Null JwkClaim Validation

```csharp
[Fact]
public void MsAuth10AtPop_ThrowsWithNullJwkClaimTest()
{
    // Arrange
    IConfidentialClientApplication app = CreateBuilder();
    var popPublicKey = "pop_key";

    // Act & Assert
    Assert.Throws<ArgumentNullException>(() => MsAuth10AtPop.WithAtPop(
        app.AcquireTokenForClient(new[] { TestConstants.Scopes }),
        popPublicKey, 
        null));  // Invalid: null
}
```

### Integration Tests

**Scenario:** End-to-end token acquisition and API call

```csharp
[Fact]
public async Task IntegrationTest_AcquireTokenAndCallApi()
{
    // Setup
    var (keyId, jwkClaim) = GeneratePopKey();
    
    var app = ConfidentialClientApplicationBuilder
        .Create(TestConfig.ClientId)
        .WithCertificate(TestConfig.Certificate)
        .WithAuthority(TestConfig.Authority)
        .WithExperimentalFeatures()
        .Build();
    
    // Acquire PoP token
    var result = await app.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" })
        .WithAtPop(keyId, jwkClaim)
        .ExecuteAsync();
    
    // Verify token type
    Assert.Equal("pop", result.TokenType);
    
    // Call API
    var httpClient = new HttpClient();
    httpClient.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Bearer", result.AccessToken);
    
    var response = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users");
    
    // Verify success
    Assert.True(response.IsSuccessStatusCode);
}
```

---

## Troubleshooting

### Common Issues

#### Issue 1: "Experimental features not enabled"

**Error:**
```
InvalidOperationException: Authentication operations require experimental features to be enabled.
```

**Solution:**
```csharp
var app = ConfidentialClientApplicationBuilder.Create(clientId)
    .WithExperimentalFeatures()  // Add this line
    .Build();
```

#### Issue 2: "ArgumentException: popPublicKey cannot be null or whitespace"

**Error:**
```
ArgumentException: Value cannot be null or whitespace. (Parameter 'popPublicKey')
```

**Solution:** Ensure `PopPublicKey` is set in `TokenAcquisitionOptions`:
```csharp
var options = new TokenAcquisitionOptions
{
    PopPublicKey = "your-key-id",  // Must not be null/empty
    PopClaim = "{...}"
};
```

#### Issue 3: "Token type mismatch"

**Error:**
```
MsalServiceException: Token type 'Bearer' does not match expected type 'pop'
```

**Possible Causes:**
1. Azure AD not configured to support PoP tokens
2. Missing `token_type=pop` parameter in request
3. Tenant/app not whitelisted for MSAuth 1.0

**Solution:** Verify Azure AD configuration and check `GetTokenRequestParams()` output.

#### Issue 4: "Deprecated pinned certificate warning"

**Warning:**
```
MSAuth POP configured with pinned certificate. This configuration is being deprecated.
```

**Solution:** Migrate to SN/I mode:
```csharp
var mergedOptions = new MergedOptions
{
    SendX5C = true  // Enable SN/I mode
};
```

---

## Advanced Topics

### Custom Key Storage

```csharp
public interface IPopKeyStore
{
    Task<(string KeyId, string JwkClaim)> GetCurrentKeyAsync();
    Task<RSA> GetPrivateKeyAsync(string keyId);
    Task RotateKeyAsync();
}

public class AzureKeyVaultPopKeyStore : IPopKeyStore
{
    private readonly KeyClient _keyClient;
    
    public async Task<(string KeyId, string JwkClaim)> GetCurrentKeyAsync()
    {
        var key = await _keyClient.GetKeyAsync("pop-key");
        var jwk = key.Value.Key.ToRSA();
        // Convert to JWK format...
        return (key.Value.Name, jwkJson);
    }
}
```

### Key Rotation

```csharp
public async Task RotatePopKeyAsync()
{
    // 1. Generate new key
    var (newKeyId, newJwkClaim) = GeneratePopKey();
    
    // 2. Store new key
    await keyStore.StoreKeyAsync(newKeyId, newJwkClaim);
    
    // 3. Acquire token with new key
    var result = await app.AcquireTokenForClient(scopes)
        .WithAtPop(newKeyId, newJwkClaim)
        .ExecuteAsync();
    
    // 4. Retire old key (after grace period)
    await keyStore.RetireKeyAsync(oldKeyId, TimeSpan.FromHours(24));
}
```

---

**Next:** [Security Architecture](./03-security-architecture.md)
