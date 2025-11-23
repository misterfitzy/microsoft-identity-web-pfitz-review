# MSAuth 1.0 Integration Guide and Best Practices

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Step-by-Step Integration](#step-by-step-integration)
3. [Configuration Patterns](#configuration-patterns)
4. [Best Practices](#best-practices)
5. [Performance Optimization](#performance-optimization)
6. [Production Considerations](#production-considerations)
7. [Common Pitfalls](#common-pitfalls)
8. [Migration Guide](#migration-guide)

---

## Quick Start Guide

### Prerequisites

- **.NET 6.0 or later**
- **Microsoft.Identity.Web 2.5.0+**
- **Azure AD application registration** (confidential client)
- **Client certificate** for application authentication
- **Understanding of OAuth 2.0** and JWT tokens

### 5-Minute Integration

```csharp
// 1. Install NuGet package
// Install-Package Microsoft.Identity.Web

// 2. Generate PoP key pair
using var rsa = RSA.Create(2048);
var jwk = CreateJwk(rsa);
var keyId = Guid.NewGuid().ToString();

// 3. Configure MSAL application
var app = ConfidentialClientApplicationBuilder
    .Create(clientId)
    .WithCertificate(certificate)
    .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
    .WithExperimentalFeatures()  // Required for authentication operations
    .Build();

// 4. Acquire PoP token
var result = await app.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" })
    .WithAtPop(keyId, jwk)
    .ExecuteAsync();

// 5. Use token for API calls
var httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Authorization = 
    new AuthenticationHeaderValue("Bearer", result.AccessToken);

var response = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users");
```

---

## Step-by-Step Integration

### Step 1: Register Application in Azure AD

**Azure Portal Steps:**

1. Navigate to **Azure Active Directory** → **App registrations**
2. Click **New registration**
3. Configure:
   - **Name**: Your application name
   - **Supported account types**: Single tenant (recommended for PoP)
   - **Redirect URI**: Not needed for confidential client
4. After registration:
   - Note **Application (client) ID**
   - Note **Directory (tenant) ID**

**Configure API Permissions:**

1. Go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph** → **Application permissions**
4. Add required permissions (e.g., `User.Read.All`, `Mail.Read`)
5. Click **Grant admin consent** (requires admin)

**Configure Certificate:**

1. Go to **Certificates & secrets**
2. Upload certificate (.cer file) OR use Azure Key Vault reference
3. Note the **certificate thumbprint**

---

### Step 2: Set Up .NET Application

**Install NuGet Packages:**

```bash
dotnet add package Microsoft.Identity.Web
dotnet add package Microsoft.Identity.Client
```

**Configuration (appsettings.json):**

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "ClientId": "12345678-1234-1234-1234-123456789abc",
    "ClientCertificates": [
      {
        "SourceType": "KeyVault",
        "KeyVaultUrl": "https://myvault.vault.azure.net",
        "KeyVaultCertificateName": "my-client-cert"
      }
    ]
  },
  "GraphApi": {
    "BaseUrl": "https://graph.microsoft.com/v1.0",
    "Scopes": [ "https://graph.microsoft.com/.default" ]
  }
}
```

---

### Step 3: Implement PoP Key Management

**Option A: In-Memory Key (Development/Testing)**

```csharp
public class InMemoryPopKeyStore : IPopKeyStore
{
    private string? _currentKeyId;
    private string? _currentJwk;
    private RSA? _currentRsa;

    public (string KeyId, string JwkClaim) GetCurrentKey()
    {
        if (_currentKeyId == null)
        {
            GenerateNewKey();
        }
        
        return (_currentKeyId!, _currentJwk!);
    }

    public RSA GetPrivateKey(string keyId)
    {
        if (keyId != _currentKeyId)
        {
            throw new InvalidOperationException($"Key {keyId} not found");
        }
        
        return _currentRsa!;
    }

    private void GenerateNewKey()
    {
        _currentRsa = RSA.Create(2048);
        _currentKeyId = Guid.NewGuid().ToString();
        
        var parameters = _currentRsa.ExportParameters(includePrivateParameters: false);
        _currentJwk = CreateJwk(parameters);
    }

    private string CreateJwk(RSAParameters parameters)
    {
        var jwk = new
        {
            kty = "RSA",
            e = Base64UrlEncoder.Encode(parameters.Exponent),
            n = Base64UrlEncoder.Encode(parameters.Modulus),
            alg = "RS256",
            kid = _currentKeyId
        };
        
        return JsonSerializer.Serialize(jwk);
    }
}
```

**Option B: Azure Key Vault (Production)**

```csharp
public class AzureKeyVaultPopKeyStore : IPopKeyStore
{
    private readonly KeyClient _keyClient;
    private readonly string _keyName;
    
    public AzureKeyVaultPopKeyStore(
        Uri keyVaultUri, 
        TokenCredential credential,
        string keyName = "pop-signing-key")
    {
        _keyClient = new KeyClient(keyVaultUri, credential);
        _keyName = keyName;
    }
    
    public async Task<(string KeyId, string JwkClaim)> GetCurrentKeyAsync()
    {
        // Get or create key in Key Vault
        KeyVaultKey key;
        try
        {
            key = await _keyClient.GetKeyAsync(_keyName);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Create new RSA key in Key Vault (HSM-backed)
            var createOptions = new CreateRsaKeyOptions(_keyName, hardwareProtected: true)
            {
                KeySize = 2048,
                KeyOperations = { KeyOperation.Sign, KeyOperation.Verify }
            };
            key = await _keyClient.CreateRsaKeyAsync(createOptions);
        }
        
        // Convert to JWK format
        var jwk = ConvertToJwk(key);
        
        return (key.Name, jwk);
    }
    
    public async Task<CryptographyClient> GetCryptographyClientAsync(string keyId)
    {
        var key = await _keyClient.GetKeyAsync(keyId);
        return new CryptographyClient(key.Id, new DefaultAzureCredential());
    }
    
    private string ConvertToJwk(KeyVaultKey key)
    {
        var rsaKey = key.Key.ToRSA();
        var parameters = rsaKey.ExportParameters(includePrivateParameters: false);
        
        var jwk = new
        {
            kty = "RSA",
            e = Base64UrlEncoder.Encode(parameters.Exponent),
            n = Base64UrlEncoder.Encode(parameters.Modulus),
            alg = "RS256",
            kid = key.Name
        };
        
        return JsonSerializer.Serialize(jwk);
    }
}
```

---

### Step 4: Configure Dependency Injection

**Startup.cs / Program.cs:**

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Add Microsoft.Identity.Web
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApi(Configuration.GetSection("AzureAd"))
            .EnableTokenAcquisitionToCallDownstreamApi()
            .AddInMemoryTokenCaches();  // Or AddDistributedTokenCaches()
        
        // Register PoP key store
        services.AddSingleton<IPopKeyStore>(sp =>
        {
            var keyVaultUrl = Configuration["AzureAd:KeyVaultUrl"];
            return new AzureKeyVaultPopKeyStore(
                new Uri(keyVaultUrl),
                new DefaultAzureCredential());
        });
        
        // Register token acquisition service
        services.AddScoped<IGraphApiService, GraphApiService>();
        
        // Add controllers, etc.
        services.AddControllers();
    }
}
```

---

### Step 5: Acquire and Use PoP Tokens

**Service Implementation:**

```csharp
public class GraphApiService : IGraphApiService
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IPopKeyStore _popKeyStore;
    private readonly IConfiguration _configuration;
    private readonly ILogger<GraphApiService> _logger;
    
    public GraphApiService(
        ITokenAcquisition tokenAcquisition,
        IPopKeyStore popKeyStore,
        IConfiguration configuration,
        ILogger<GraphApiService> logger)
    {
        _tokenAcquisition = tokenAcquisition;
        _popKeyStore = popKeyStore;
        _configuration = configuration;
        _logger = logger;
    }
    
    public async Task<IEnumerable<User>> GetUsersAsync()
    {
        try
        {
            // Get PoP key
            var (keyId, jwkClaim) = await _popKeyStore.GetCurrentKeyAsync();
            
            // Acquire PoP token
            var scopes = new[] { "https://graph.microsoft.com/.default" };
            var tokenOptions = new TokenAcquisitionOptions
            {
                PopPublicKey = keyId,
                PopClaim = jwkClaim
            };
            
            var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
                scopes,
                tokenAcquisitionOptions: tokenOptions);
            
            // Call Graph API
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = 
                new AuthenticationHeaderValue("Bearer", token);
            
            var response = await httpClient.GetAsync(
                "https://graph.microsoft.com/v1.0/users");
            
            response.EnsureSuccessStatusCode();
            
            var content = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<GraphUsersResponse>(content);
            
            _logger.LogInformation(
                "Retrieved {Count} users using PoP token", 
                result?.Value?.Count ?? 0);
            
            return result?.Value ?? Enumerable.Empty<User>();
        }
        catch (MsalServiceException ex)
        {
            _logger.LogError(ex, 
                "Failed to acquire PoP token: {ErrorCode} - {Message}", 
                ex.ErrorCode, ex.Message);
            throw;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, 
                "Failed to call Graph API");
            throw;
        }
    }
}
```

---

## Configuration Patterns

### Pattern 1: Azure Key Vault Integration

**Full Configuration:**

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "ClientId": "12345678-1234-1234-1234-123456789abc",
    "ClientCertificates": [
      {
        "SourceType": "KeyVault",
        "KeyVaultUrl": "https://myvault.vault.azure.net",
        "KeyVaultCertificateName": "my-client-cert"
      }
    ]
  },
  "PopKeyVault": {
    "VaultUrl": "https://myvault.vault.azure.net",
    "KeyName": "pop-signing-key"
  }
}
```

**Code:**

```csharp
services.AddSingleton<IPopKeyStore>(sp =>
{
    var vaultUrl = Configuration["PopKeyVault:VaultUrl"];
    var keyName = Configuration["PopKeyVault:KeyName"];
    
    return new AzureKeyVaultPopKeyStore(
        new Uri(vaultUrl),
        new DefaultAzureCredential(),
        keyName);
});
```

---

### Pattern 2: SN/I (Subject Name/Issuer) Mode

**Recommended for production:**

```csharp
services.AddMicrosoftIdentityWebAppAuthentication(Configuration)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddInMemoryTokenCaches();

// Configure to use SN/I
services.Configure<MicrosoftIdentityOptions>(options =>
{
    options.SendX5C = true;  // Enable SN/I mode
});
```

**Benefits:**
- ✅ More flexible certificate management
- ✅ Supports certificate rotation
- ✅ Recommended by Microsoft

---

### Pattern 3: Multi-Tenant Configuration

```csharp
public class MultiTenantPopKeyStore : IPopKeyStore
{
    private readonly IKeyVaultService _keyVault;
    private readonly ConcurrentDictionary<string, (string KeyId, string Jwk)> _tenantKeys;
    
    public async Task<(string KeyId, string JwkClaim)> GetKeyForTenantAsync(string tenantId)
    {
        return await _tenantKeys.GetOrAddAsync(
            tenantId,
            async tid => await GenerateKeyForTenantAsync(tid));
    }
    
    private async Task<(string, string)> GenerateKeyForTenantAsync(string tenantId)
    {
        var keyName = $"pop-key-{tenantId}";
        // Generate or retrieve tenant-specific key
        // ...
    }
}
```

---

## Best Practices

### Security Best Practices

#### 1. Use Hardware Security Modules (HSMs)

```csharp
// ✅ RECOMMENDED: HSM-backed key storage
var createOptions = new CreateRsaKeyOptions("pop-key", hardwareProtected: true)
{
    KeySize = 2048,
    KeyOperations = { KeyOperation.Sign, KeyOperation.Verify }
};

// ❌ AVOID: Software-only key storage in production
var rsa = RSA.Create(2048);  // Vulnerable to memory dumps
```

#### 2. Implement Key Rotation

```csharp
public class KeyRotationService : BackgroundService
{
    private readonly IPopKeyStore _keyStore;
    private readonly TimeSpan _rotationInterval = TimeSpan.FromDays(90);
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _keyStore.RotateKeyAsync();
                _logger.LogInformation("PoP key rotated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Key rotation failed");
            }
            
            await Task.Delay(_rotationInterval, stoppingToken);
        }
    }
}
```

#### 3. Never Log Sensitive Data

```csharp
// ❌ INSECURE: Logging tokens or keys
_logger.LogInformation($"Token: {result.AccessToken}");
_logger.LogInformation($"JWK: {jwkClaim}");

// ✅ SECURE: Log only metadata
_logger.LogInformation(
    "Token acquired: type={TokenType}, expires={ExpiresOn}, scopes={Scopes}",
    result.TokenType,
    result.ExpiresOn,
    string.Join(",", result.Scopes));
```

#### 4. Validate All Inputs

```csharp
public static class ParameterValidation
{
    public static void ValidateKeyId(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException("Key ID cannot be null or whitespace", nameof(keyId));
        }
        
        if (keyId.Length > 256)
        {
            throw new ArgumentException("Key ID exceeds maximum length", nameof(keyId));
        }
        
        if (!Regex.IsMatch(keyId, @"^[a-zA-Z0-9\-_]+$"))
        {
            throw new ArgumentException("Key ID contains invalid characters", nameof(keyId));
        }
    }
}
```

#### 5. Use Secure Token Cache

```csharp
// ✅ RECOMMENDED: Distributed cache with encryption
services.AddDistributedSqlServerCache(options =>
{
    options.ConnectionString = Configuration["CacheConnectionString"];
    options.SchemaName = "dbo";
    options.TableName = "TokenCache";
});

services.AddDistributedTokenCaches();

// ❌ AVOID in production: In-memory cache (lost on restart)
services.AddInMemoryTokenCaches();
```

---

### Performance Best Practices

#### 1. Cache PoP Keys

```csharp
public class CachedPopKeyStore : IPopKeyStore
{
    private readonly IPopKeyStore _innerStore;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cacheDuration = TimeSpan.FromHours(24);
    
    public async Task<(string KeyId, string JwkClaim)> GetCurrentKeyAsync()
    {
        const string cacheKey = "current-pop-key";
        
        if (_cache.TryGetValue(cacheKey, out (string, string) cachedKey))
        {
            return cachedKey;
        }
        
        var key = await _innerStore.GetCurrentKeyAsync();
        
        _cache.Set(cacheKey, key, _cacheDuration);
        
        return key;
    }
}
```

#### 2. Use Token Cache Efficiently

```csharp
// ✅ EFFICIENT: Reuse tokens from cache
var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
    scopes,
    tokenAcquisitionOptions: options);
// MSAL automatically checks cache first

// ❌ INEFFICIENT: Force refresh on every call
var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
    scopes,
    tokenAcquisitionOptions: new TokenAcquisitionOptions
    {
        ForceRefresh = true,  // Bypasses cache
        PopPublicKey = keyId,
        PopClaim = jwkClaim
    });
```

#### 3. Implement Circuit Breaker

```csharp
public class ResilientGraphApiService : IGraphApiService
{
    private readonly IGraphApiService _innerService;
    private readonly CircuitBreakerPolicy _circuitBreaker;
    
    public ResilientGraphApiService(IGraphApiService innerService)
    {
        _innerService = innerService;
        
        _circuitBreaker = Policy
            .Handle<HttpRequestException>()
            .Or<MsalServiceException>()
            .CircuitBreakerAsync(
                exceptionsAllowedBeforeBreaking: 5,
                durationOfBreak: TimeSpan.FromSeconds(30),
                onBreak: (ex, duration) =>
                {
                    _logger.LogWarning(
                        "Circuit breaker opened for {Duration}s due to: {Exception}",
                        duration.TotalSeconds, ex.Message);
                },
                onReset: () =>
                {
                    _logger.LogInformation("Circuit breaker reset");
                });
    }
    
    public async Task<IEnumerable<User>> GetUsersAsync()
    {
        return await _circuitBreaker.ExecuteAsync(
            async () => await _innerService.GetUsersAsync());
    }
}
```

#### 4. Parallel Token Acquisition (When Safe)

```csharp
// For multiple independent API calls
var tasks = new[]
{
    AcquireTokenAndCallApiAsync("api1", scopes1),
    AcquireTokenAndCallApiAsync("api2", scopes2),
    AcquireTokenAndCallApiAsync("api3", scopes3)
};

var results = await Task.WhenAll(tasks);

async Task<Result> AcquireTokenAndCallApiAsync(string apiName, string[] scopes)
{
    var (keyId, jwk) = await _popKeyStore.GetCurrentKeyAsync();
    var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
        scopes,
        tokenAcquisitionOptions: new TokenAcquisitionOptions
        {
            PopPublicKey = keyId,
            PopClaim = jwk
        });
    
    return await CallApiAsync(apiName, token);
}
```

---

## Production Considerations

### Monitoring and Observability

#### 1. Application Insights Integration

```csharp
public class MonitoredGraphApiService : IGraphApiService
{
    private readonly TelemetryClient _telemetry;
    
    public async Task<IEnumerable<User>> GetUsersAsync()
    {
        using var operation = _telemetry.StartOperation<DependencyTelemetry>("GraphApi.GetUsers");
        
        try
        {
            var result = await _innerService.GetUsersAsync();
            
            operation.Telemetry.Success = true;
            operation.Telemetry.ResultCode = "200";
            
            _telemetry.TrackMetric("GraphApi.Users.Count", result.Count());
            
            return result;
        }
        catch (Exception ex)
        {
            operation.Telemetry.Success = false;
            operation.Telemetry.ResultCode = "500";
            
            _telemetry.TrackException(ex);
            
            throw;
        }
    }
}
```

#### 2. Custom Metrics

```csharp
public class MetricsTracker
{
    private readonly TelemetryClient _telemetry;
    
    public void TrackTokenAcquisition(TimeSpan duration, bool success, string tokenType)
    {
        _telemetry.TrackMetric("TokenAcquisition.Duration", duration.TotalMilliseconds,
            new Dictionary<string, string>
            {
                { "Success", success.ToString() },
                { "TokenType", tokenType }
            });
        
        _telemetry.TrackEvent("TokenAcquired", new Dictionary<string, string>
        {
            { "TokenType", tokenType },
            { "Duration", duration.TotalMilliseconds.ToString() }
        });
    }
}
```

---

### Health Checks

```csharp
public class PopTokenHealthCheck : IHealthCheck
{
    private readonly IPopKeyStore _keyStore;
    private readonly ITokenAcquisition _tokenAcquisition;
    
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Check key availability
            var (keyId, jwk) = await _keyStore.GetCurrentKeyAsync();
            
            if (string.IsNullOrEmpty(keyId) || string.IsNullOrEmpty(jwk))
            {
                return HealthCheckResult.Unhealthy("PoP key not available");
            }
            
            // Attempt token acquisition
            var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
                new[] { "https://graph.microsoft.com/.default" },
                tokenAcquisitionOptions: new TokenAcquisitionOptions
                {
                    PopPublicKey = keyId,
                    PopClaim = jwk
                });
            
            if (string.IsNullOrEmpty(token))
            {
                return HealthCheckResult.Degraded("Token acquisition returned null");
            }
            
            return HealthCheckResult.Healthy("PoP token acquisition successful");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("PoP token acquisition failed", ex);
        }
    }
}

// Register in Startup.cs
services.AddHealthChecks()
    .AddCheck<PopTokenHealthCheck>("pop-token", tags: new[] { "ready" });
```

---

## Common Pitfalls

### Pitfall 1: Forgetting `.WithExperimentalFeatures()`

```csharp
// ❌ ERROR: Will throw exception
var app = ConfidentialClientApplicationBuilder.Create(clientId)
    .WithCertificate(certificate)
    .Build();

await app.AcquireTokenForClient(scopes)
    .WithAtPop(keyId, jwk)  // Throws: Experimental features not enabled
    .ExecuteAsync();

// ✅ CORRECT: Enable experimental features
var app = ConfidentialClientApplicationBuilder.Create(clientId)
    .WithCertificate(certificate)
    .WithExperimentalFeatures()  // Required!
    .Build();
```

---

### Pitfall 2: Incorrect JWK Format

```csharp
// ❌ ERROR: JWK as object instead of JSON string
var jwkObject = new { kty = "RSA", e = "AQAB", n = "..." };
await app.AcquireTokenForClient(scopes)
    .WithAtPop(keyId, jwkObject)  // Wrong type!
    .ExecuteAsync();

// ✅ CORRECT: JWK as JSON string
var jwkString = JsonSerializer.Serialize(new { kty = "RSA", e = "AQAB", n = "..." });
await app.AcquireTokenForClient(scopes)
    .WithAtPop(keyId, jwkString)  // Correct!
    .ExecuteAsync();
```

---

### Pitfall 3: Not Base64URL-Encoding JWK Components

```csharp
// ❌ ERROR: Using regular Base64 instead of Base64URL
var jwk = new
{
    kty = "RSA",
    e = Convert.ToBase64String(parameters.Exponent),  // Wrong encoding!
    n = Convert.ToBase64String(parameters.Modulus)    // Wrong encoding!
};

// ✅ CORRECT: Use Base64URL encoding
var jwk = new
{
    kty = "RSA",
    e = Base64UrlEncoder.Encode(parameters.Exponent),  // Correct!
    n = Base64UrlEncoder.Encode(parameters.Modulus)    // Correct!
};
```

---

### Pitfall 4: Key Rotation Without Grace Period

```csharp
// ❌ PROBLEM: Immediate key retirement breaks in-flight tokens
await RotateKeyAsync();
await RetireOldKeyAsync();  // Tokens using old key fail immediately!

// ✅ SOLUTION: Grace period for old tokens to expire
await RotateKeyAsync();
await Task.Delay(TimeSpan.FromHours(1));  // Wait for old tokens to expire
await RetireOldKeyAsync();
```

---

## Migration Guide

### From Bearer Tokens to MSAuth 1.0 PoP

**Step 1: Update Code (Backward Compatible)**

```csharp
// Before: Bearer token
var token = await _tokenAcquisition.GetAccessTokenForAppAsync(scopes);

// After: PoP token (with feature flag)
var token = await _tokenAcquisition.GetAccessTokenForAppAsync(
    scopes,
    tokenAcquisitionOptions: _configuration.GetValue<bool>("UsePopTokens")
        ? new TokenAcquisitionOptions
          {
              PopPublicKey = await GetKeyIdAsync(),
              PopClaim = await GetJwkAsync()
          }
        : null);
```

**Step 2: Gradual Rollout**

```csharp
public class TokenAcquisitionStrategy
{
    public async Task<string> GetTokenAsync(string[] scopes)
    {
        // Use feature flag or A/B testing
        if (await _featureFlags.IsEnabledAsync("PopTokens"))
        {
            return await AcquirePopTokenAsync(scopes);
        }
        else
        {
            return await AcquireBearerTokenAsync(scopes);
        }
    }
}
```

**Step 3: Monitor and Validate**

```csharp
// Track both token types during migration
_metrics.TrackTokenType(result.TokenType);
_metrics.TrackTokenSuccess(result.TokenType, success: true);
```

---

## Summary

This integration guide covers:

✅ **Quick start** (5-minute setup)
✅ **Step-by-step integration** (production-ready)
✅ **Configuration patterns** (Key Vault, SN/I, multi-tenant)
✅ **Best practices** (security, performance, resilience)
✅ **Production considerations** (monitoring, health checks)
✅ **Common pitfalls** (and how to avoid them)
✅ **Migration guide** (bearer → PoP tokens)

**Key Recommendations:**

1. **Use Azure Key Vault** with HSM backing for production
2. **Enable SN/I mode** (`SendX5C = true`)
3. **Implement key rotation** (90-day cycle)
4. **Never log sensitive data** (tokens, keys, JWKs)
5. **Use distributed token cache** for scale
6. **Monitor and alert** on token acquisition failures
7. **Test thoroughly** before production deployment

---

**Complete Documentation Set:**

1. [Protocol Overview](./01-msauth10-overview.md)
2. [Technical Implementation](./02-technical-implementation.md)
3. [Security Architecture](./03-security-architecture.md)
4. [Token Flow Diagrams](./04-token-flow-diagrams.md)
5. **Integration Guide** (this document)

**For Questions or Support:**
- GitHub Issues: [microsoft-identity-web](https://github.com/AzureAD/microsoft-identity-web/issues)
- Stack Overflow: Tag `microsoft-identity-web`
- Microsoft Docs: [Microsoft Identity Platform](https://learn.microsoft.com/azure/active-directory/develop/)
