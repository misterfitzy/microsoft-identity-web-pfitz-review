# MSAuth 1.0 Security Architecture

## Table of Contents

1. [Security Model Overview](#security-model-overview)
2. [Threat Analysis](#threat-analysis)
3. [Cryptographic Foundations](#cryptographic-foundations)
4. [Attack Surface Analysis](#attack-surface-analysis)
5. [Security Controls](#security-controls)
6. [Compliance and Standards](#compliance-and-standards)
7. [Security Best Practices](#security-best-practices)

---

## Security Model Overview

### Defense in Depth Strategy

MSAuth 1.0 AT-POP implements multiple layers of security controls, creating a robust defense-in-depth architecture:

```
┌────────────────────────────────────────────────────────────────┐
│                    Defense Layers (Outside → Inside)            │
└────────────────────────────────────────────────────────────────┘

Layer 7: Authorization (Scope/Role Validation)
         ↓ "Does the token grant access to this resource?"
         
Layer 6: Token Integrity (JWT Signature Verification)
         ↓ "Was this token issued by Azure AD?"
         
Layer 5: Token Binding Validation (cnf claim verification)
         ↓ "Is this token bound to the correct key?"
         
Layer 4: Proof of Possession (Signature with private key)
         ↓ "Does the client possess the private key?"
         
Layer 3: Client Authentication (client_assertion)
         ↓ "Is this the legitimate client application?"
         
Layer 2: Certificate Validation (X.509 validation)
         ↓ "Is the certificate valid and trusted?"
         
Layer 1: Transport Security (TLS 1.2+ with cipher suite validation)
         ↓ "Is the communication channel secure?"

Layer 0: Network Security (Firewall, DDoS protection, WAF)
         "Can the client reach the authorization server?"
```

### Security Principles

MSAuth 1.0 AT-POP adheres to fundamental security principles:

| Principle | Implementation | Benefit |
|-----------|----------------|---------|
| **Least Privilege** | Tokens scoped to specific resources/permissions | Limits blast radius of compromise |
| **Defense in Depth** | Multiple validation layers | Single control failure doesn't break security |
| **Cryptographic Binding** | Token bound to client key via `cnf` claim | Prevents token theft/replay |
| **Zero Trust** | Every request validated independently | No implicit trust based on prior authentication |
| **Secure by Default** | PoP mode requires explicit configuration | Prevents accidental insecure deployments |
| **Fail Securely** | Invalid tokens rejected, no fallback | Errors don't weaken security posture |

---

## Threat Analysis

### Threat Model

**Adversary Capabilities:**
- Network eavesdropping (passive and active MITM)
- Compromise of token storage (memory, cache, logs)
- Malicious insider access to systems
- Social engineering attacks
- Cryptographic attacks (if weak algorithms used)

**Assets to Protect:**
1. **Access Tokens** (primary target)
2. **Private Keys** (critical - compromise enables token use)
3. **Client Credentials** (certificates, secrets)
4. **User Data** (protected by access tokens)

---

### STRIDE Threat Analysis

#### 1. Spoofing Identity

**Threat:** Attacker impersonates legitimate client application

**MSAuth 1.0 Mitigations:**

| Attack Vector | Bearer Token Defense | MSAuth 1.0 PoP Defense |
|---------------|---------------------|----------------------|
| Stolen token used by attacker | ❌ **None** - Token is bearer credential | ✅ **PoP binding** - Requires private key |
| Forged token | ✅ JWT signature verification | ✅ JWT signature verification |
| Replay captured token | ❌ **Limited** - Valid until expiry | ✅ **Strong** - Requires key possession |

**Implementation:**

```csharp
// Client authentication (Layer 3)
client_assertion = JWT.Sign(
    payload: { aud, iss, sub, jti, nbf, exp },
    privateKey: clientCertificatePrivateKey
);

// Token binding (Layer 5)
req_cnf = Base64UrlEncode(publicKeyJWK);
token_type = "pop";

// Result: Token bound to specific client + specific key
```

**Security Level:** 🟢 **Excellent** (multi-factor authentication)

---

#### 2. Tampering

**Threat:** Attacker modifies token or request parameters

**MSAuth 1.0 Mitigations:**

| Attack | Defense Mechanism | Effectiveness |
|--------|------------------|---------------|
| Modify JWT claims | JWT signature invalidated | 🟢 Complete |
| Modify req_cnf | Client assertion fails (wrong key) | 🟢 Complete |
| Modify token_type | Token request rejected | 🟢 Complete |
| Modify API request | (Would require PoP signature if implemented) | 🟡 Partial* |

*Note: Current implementation doesn't sign individual API requests; full SHR (Signed HTTP Requests) would provide this.

**Implementation:**

```json
// Token structure (tamper-evident)
{
  "header": { "alg": "RS256", "typ": "JWT" },
  "payload": {
    "aud": "https://graph.microsoft.com",
    "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
    "cnf": { "kid": "key-identifier" },  // Token binding
    "exp": 1640003600
  },
  "signature": "..."  // Any payload change invalidates this
}
```

**Security Level:** 🟢 **Excellent** for token; 🟡 **Good** for API requests

---

#### 3. Repudiation

**Threat:** Client denies making a request or obtaining a token

**MSAuth 1.0 Mitigations:**

1. **Audit Logging:** Azure AD logs all token issuance events
2. **JWT `jti` claim:** Unique token identifier for audit trails
3. **Cryptographic Signatures:** Non-repudiable proof of client involvement
4. **Key Binding:** Ties token to specific client instance

**Audit Record Example:**

```json
{
  "timestamp": "2023-12-20T15:30:00Z",
  "event": "TokenIssued",
  "clientId": "12345678-1234-1234-1234-123456789abc",
  "tokenId": "unique-jti-value",
  "tokenType": "pop",
  "keyId": "key-identifier",
  "scopes": ["https://graph.microsoft.com/.default"],
  "clientCertificateThumbprint": "ABC123...",
  "ipAddress": "203.0.113.42"
}
```

**Security Level:** 🟢 **Excellent** (comprehensive audit trail)

---

#### 4. Information Disclosure

**Threat:** Sensitive information leaked through tokens, logs, or network traffic

**MSAuth 1.0 Mitigations:**

| Information Type | Protection Mechanism | Residual Risk |
|-----------------|---------------------|---------------|
| Access Token | TLS encryption in transit | 🟢 Low (if TLS configured correctly) |
| Token in Logs | Should not log tokens | 🟡 Medium (depends on app logging practices) |
| Token in Cache | Encrypted token cache | 🟢 Low (MSAL default) |
| Private Key | Secure key storage (HSM, Key Vault) | 🟢 Low (if configured) / 🔴 High (if not) |
| JWK Public Key | Public by design | 🟢 None (public key is safe to disclose) |

**Critical Security Control:**

```csharp
// NEVER log the access token
_logger.LogInformation($"Token acquired: {result.AccessToken}");  // ❌ INSECURE

// Log only metadata
_logger.LogInformation(
    "Token acquired: type={TokenType}, expires={ExpiresOn}, scopes={Scopes}",
    result.TokenType,
    result.ExpiresOn,
    string.Join(",", result.Scopes));  // ✅ SECURE
```

**Additional Controls:**

1. **TLS 1.2+ Required:** Enforces strong transport encryption
2. **Token Cache Encryption:** MSAL encrypts tokens at rest (DPAPI on Windows)
3. **Memory Protection:** Sensitive data cleared after use (where possible)
4. **req_cnf Encoding:** Base64url encoding prevents injection attacks

**Security Level:** 🟢 **Excellent** (with proper configuration)

---

#### 5. Denial of Service (DoS)

**Threat:** Attacker disrupts service availability

**MSAuth 1.0 Implications:**

| DoS Vector | Impact | Mitigation |
|------------|--------|-----------|
| Flood token endpoint | Azure AD rate limiting | Azure infrastructure |
| Expensive crypto operations | Client CPU exhaustion | Key caching, async operations |
| Large JWK claims | Request size limits | Azure AD validation |

**Performance Considerations:**

```csharp
// ❌ INEFFICIENT: Generate new key for every request
foreach (var request in requests)
{
    var (keyId, jwk) = GeneratePopKey();  // Expensive RSA generation
    await AcquireTokenAsync(keyId, jwk);
}

// ✅ EFFICIENT: Reuse key across requests
var (keyId, jwk) = GeneratePopKey();  // Generate once
foreach (var request in requests)
{
    await AcquireTokenAsync(keyId, jwk);  // Reuse key
}
```

**Security Level:** 🟡 **Good** (relies on Azure infrastructure)

---

#### 6. Elevation of Privilege

**Threat:** Attacker gains unauthorized access or permissions

**MSAuth 1.0 Mitigations:**

| Attack Scenario | Defense | Effectiveness |
|-----------------|---------|---------------|
| Stolen bearer token used for unauthorized access | Token binding to key | 🟢 Prevented |
| Token scope escalation | Scope validated at API | 🟢 Prevented |
| Token reuse across clients | `cnf` claim validates key match | 🟢 Prevented |
| Compromised API using token elsewhere | `aud` claim validates audience | 🟢 Prevented |

**Scope Validation Example:**

```csharp
// API validates token scopes
[Authorize]
[RequiredScope("User.Read.All")]
public IActionResult GetUsers()
{
    // Token must have User.Read.All scope
    // MSAuth 1.0 ensures token is bound to correct client
}
```

**Security Level:** 🟢 **Excellent** (comprehensive authorization checks)

---

## Cryptographic Foundations

### Asymmetric Cryptography

MSAuth 1.0 relies on **public-key cryptography** (asymmetric encryption):

```
┌──────────────────────────────────────────────────────────────┐
│            Asymmetric Key Pair (RSA 2048-bit)                 │
└──────────────────────────────────────────────────────────────┘

┌─────────────────────┐              ┌────────────────────────┐
│   Private Key       │              │   Public Key           │
│   (Secret)          │              │   (Shared)             │
├─────────────────────┤              ├────────────────────────┤
│ • Kept secure       │              │ • Included in req_cnf  │
│ • Never transmitted │              │ • Sent to Azure AD     │
│ • Used to sign      │              │ • Embedded in token    │
│ • Proves possession │              │ • Used to verify       │
└─────────────────────┘              └────────────────────────┘
         │                                      │
         └──────────────┬───────────────────────┘
                        │
                 Mathematically Linked
              (RSA algorithm properties)
```

### Supported Algorithms

**Client Assertion Signing:**
- **RS256** (RSA with SHA-256) - Default
- **RS384** (RSA with SHA-384)
- **RS512** (RSA with SHA-512)
- **ES256** (ECDSA with P-256 and SHA-256)
- **ES384** (ECDSA with P-384 and SHA-384)
- **ES512** (ECDSA with P-521 and SHA-512)

**Token Signature Validation:**
- **RS256** - Default for Azure AD v2.0 tokens
- **RS384**, **RS512** - Also supported

**Key Sizes:**

| Algorithm | Minimum Key Size | Recommended | Security Level |
|-----------|-----------------|-------------|----------------|
| RSA | 2048 bits | 3072 bits | 112-128 bits |
| ECDSA P-256 | 256 bits | 256 bits | 128 bits |
| ECDSA P-384 | 384 bits | 384 bits | 192 bits |

**Security Recommendations:**

```csharp
// ✅ RECOMMENDED: RSA 2048 or higher
using var rsa = RSA.Create(2048);

// ✅ BETTER: RSA 3072 for higher security
using var rsa = RSA.Create(3072);

// ❌ INSECURE: RSA 1024 (deprecated)
using var rsa = RSA.Create(1024);  // DO NOT USE
```

---

### JWT Security Properties

**JSON Web Token (JWT) Structure:**

```
┌────────────────────────────────────────────────────────────────┐
│  HEADER.PAYLOAD.SIGNATURE                                      │
└────────────────────────────────────────────────────────────────┘

HEADER (Base64URL-encoded):
{
  "alg": "RS256",        // Signing algorithm
  "typ": "JWT",          // Token type
  "kid": "key-id"        // Key identifier (for signature verification)
}

PAYLOAD (Base64URL-encoded):
{
  "iss": "https://...",  // Issuer (Azure AD)
  "aud": "https://...",  // Audience (API)
  "exp": 1640003600,     // Expiration (Unix timestamp)
  "nbf": 1640000000,     // Not before
  "iat": 1640000000,     // Issued at
  "cnf": {               // Confirmation claim (PoP binding)
    "kid": "key-id"
  },
  "scp": "User.Read"     // Scopes
}

SIGNATURE (Raw bytes):
RS256(
  Base64URL(HEADER) + "." + Base64URL(PAYLOAD),
  Azure_AD_Private_Key
)
```

**Cryptographic Guarantees:**

1. **Authenticity:** Signature proves token issued by Azure AD
2. **Integrity:** Any modification invalidates signature
3. **Binding:** `cnf` claim cryptographically ties token to key
4. **Time-bound:** `exp` and `nbf` enforce temporal validity

---

## Attack Surface Analysis

### Attack Vectors and Mitigations

#### Vector 1: Token Interception (Network Sniffing)

**Attack:** Attacker captures token in transit

**Bearer Token Impact:** 🔴 **Critical** - Stolen token is fully usable

**MSAuth 1.0 PoP Impact:** 🟢 **Low** - Token useless without private key

**Mitigation Stack:**

```
Layer 1: TLS 1.2+ (encrypts token in transit)
         ↓
Layer 2: PoP Binding (token requires private key)
         ↓
Layer 3: Certificate Pinning (optional, prevents MITM)
```

**Residual Risk:** 🟢 Minimal (requires TLS compromise + private key theft)

---

#### Vector 2: Token Theft from Cache/Storage

**Attack:** Attacker reads token from cache/memory/disk

**Bearer Token Impact:** 🔴 **Critical** - Stolen token is fully usable

**MSAuth 1.0 PoP Impact:** 🟡 **Medium** - Token requires private key (stored separately)

**Mitigation:**

```csharp
// MSAL token cache encryption (Windows: DPAPI)
services.AddDistributedTokenCaches();  // Encrypted cache

// Separate key storage
services.AddSingleton<IPopKeyStore, AzureKeyVaultPopKeyStore>();
```

**Best Practice:** Store private keys in hardware security module (HSM) or Key Vault

**Residual Risk:** 🟡 Medium (if keys not in HSM) / 🟢 Low (if keys in HSM)

---

#### Vector 3: Man-in-the-Middle (MITM)

**Attack:** Attacker intercepts and potentially modifies requests

**MSAuth 1.0 Defenses:**

1. **TLS Mutual Authentication:** Client validates server certificate
2. **JWT Signature:** Token tampering detected
3. **Client Assertion:** MITM cannot forge valid assertion

**Attack Scenario:**

```
Client ──(TLS)──► [MITM] ──(TLS)──► Azure AD
                    ↓
               Intercepts request
               Attempts to modify req_cnf
                    ↓
               Azure AD rejects (signature mismatch)
```

**Residual Risk:** 🟢 Low (requires TLS compromise)

---

#### Vector 4: Key Compromise

**Attack:** Attacker steals private key

**Impact:** 🔴 **Critical** - Can use all tokens bound to that key

**Mitigations:**

1. **Key Rotation:** Regular key rotation limits exposure window
2. **Hardware Security Modules:** Store keys in tamper-resistant hardware
3. **Key Monitoring:** Detect unauthorized key usage
4. **Token Revocation:** Revoke tokens if key compromise detected

**Key Rotation Strategy:**

```csharp
public async Task RotateKeyAsync()
{
    // 1. Generate new key
    var (newKeyId, newJwk) = GeneratePopKey();
    
    // 2. Store in Key Vault
    await keyVault.StoreKeyAsync(newKeyId, newJwk);
    
    // 3. Use new key for future tokens
    currentKeyId = newKeyId;
    
    // 4. Retire old key after grace period (24 hours)
    await ScheduleKeyRetirementAsync(oldKeyId, TimeSpan.FromHours(24));
}
```

**Residual Risk:** 🟡 Medium (time-boxed by rotation frequency)

---

#### Vector 5: Cryptographic Attacks

**Attack Types:**

1. **Brute Force:** Exhaustive key search
2. **Factorization:** Breaking RSA by factoring modulus
3. **Algorithm Attacks:** Exploiting weaknesses in crypto algorithms

**Defenses:**

| Attack | Mitigation | Effectiveness |
|--------|-----------|---------------|
| Brute force RSA 2048 | Key size (2^2048 space) | 🟢 Complete (infeasible) |
| Factor RSA modulus | Large key size | 🟢 Complete (no known efficient algorithm) |
| SHA-256 collision | SHA-256 collision resistance | 🟢 Complete (2^128 security) |
| Weak RNG | Use cryptographically secure RNG | 🟢 Complete (if implemented correctly) |

**Crypto Best Practices:**

```csharp
// ✅ Use .NET's secure RNG
using var rng = RandomNumberGenerator.Create();
byte[] randomBytes = new byte[32];
rng.GetBytes(randomBytes);

// ❌ INSECURE: Don't use Random class for crypto
var random = new Random();  // NOT cryptographically secure
```

**Residual Risk:** 🟢 Minimal (with strong algorithms and key sizes)

---

## Security Controls

### Control Matrix

| Control ID | Control Name | Type | Criticality | Implementation Status |
|-----------|--------------|------|-------------|-----------------------|
| **AUTH-01** | Client Certificate Authentication | Preventive | Critical | ✅ Implemented |
| **AUTH-02** | PoP Token Binding | Preventive | Critical | ✅ Implemented |
| **AUTH-03** | JWT Signature Verification | Detective | Critical | ✅ Implemented (Azure AD) |
| **CRYPTO-01** | TLS 1.2+ Enforcement | Preventive | Critical | ✅ Implemented (Azure) |
| **CRYPTO-02** | RSA 2048+ Key Size | Preventive | High | ✅ Recommended |
| **CRYPTO-03** | Secure Key Storage | Preventive | Critical | ⚠️ Configuration-dependent |
| **DATA-01** | Token Cache Encryption | Preventive | High | ✅ Implemented (MSAL) |
| **DATA-02** | Token Logging Prevention | Preventive | High | ⚠️ Application-dependent |
| **AUDIT-01** | Token Issuance Logging | Detective | Medium | ✅ Implemented (Azure AD) |
| **VALID-01** | Token Expiration Check | Preventive | Critical | ✅ Implemented (MSAL/API) |
| **VALID-02** | Audience Validation | Preventive | Critical | ✅ Implemented (API) |
| **VALID-03** | Issuer Validation | Preventive | Critical | ✅ Implemented (API) |

---

### Critical Security Configurations

#### 1. Enforce TLS 1.2+

```csharp
// ASP.NET Core - Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.Configure<HttpsRedirectionOptions>(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
        options.HttpsPort = 443;
    });
}

public void Configure(IApplicationBuilder app)
{
    app.UseHttpsRedirection();  // Force HTTPS
}
```

#### 2. Secure Key Storage (Azure Key Vault)

```csharp
public class AzureKeyVaultPopKeyStore : IPopKeyStore
{
    private readonly KeyClient _keyClient;
    private readonly SecretClient _secretClient;
    
    public AzureKeyVaultPopKeyStore(Uri keyVaultUri, TokenCredential credential)
    {
        _keyClient = new KeyClient(keyVaultUri, credential);
        _secretClient = new SecretClient(keyVaultUri, credential);
    }
    
    public async Task<(string KeyId, string JwkClaim)> GetCurrentKeyAsync()
    {
        // Retrieve key from Key Vault (HSM-backed)
        var key = await _keyClient.GetKeyAsync("pop-signing-key");
        
        // Convert to JWK
        var jwk = ConvertToJwk(key.Value);
        
        return (key.Value.Name, jwk);
    }
}
```

#### 3. Token Validation Configuration

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://login.microsoftonline.com/{tenant}/v2.0";
        options.Audience = "https://graph.microsoft.com";
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5),  // Allow 5 min clock skew
            
            // PoP-specific validation
            ValidTypes = new[] { "JWT" },
            ValidAlgorithms = new[] { "RS256", "RS384", "RS512" }
        };
    });
```

---

## Compliance and Standards

### Regulatory Compliance

MSAuth 1.0 AT-POP supports compliance with:

| Regulation | Requirement | MSAuth 1.0 Support |
|-----------|-------------|-------------------|
| **PCI DSS 4.0** | Strong authentication for access to cardholder data | ✅ Yes - MFA + PoP |
| **HIPAA** | Access controls for PHI | ✅ Yes - Token binding |
| **SOC 2 Type II** | Secure authentication mechanisms | ✅ Yes - Comprehensive controls |
| **GDPR** | Data protection by design | ✅ Yes - Minimal data exposure |
| **NIST 800-63B** | Authenticator Assurance Level 2 (AAL2) | ✅ Yes - Cryptographic auth |
| **FedRAMP** | Strong authentication for federal systems | ✅ Yes - Approved algorithms |

---

### Standards Compliance

#### NIST Guidelines

**NIST SP 800-63B (Digital Identity Guidelines):**

| Requirement | Implementation |
|-------------|----------------|
| Cryptographic authenticator | ✅ X.509 certificate (client authentication) |
| Proof of possession | ✅ Private key signature |
| Resistant to eavesdropping | ✅ TLS + PoP binding |
| Resistant to replay | ✅ Token expiration + binding |
| Verifier impersonation resistant | ✅ Mutual TLS |

**NIST SP 800-57 (Key Management):**

| Guideline | Compliance |
|-----------|-----------|
| RSA 2048-bit minimum | ✅ Enforced |
| Key rotation | ⚠️ Application responsibility |
| Secure key storage | ⚠️ Configuration-dependent |

---

#### OWASP Top 10 Mitigations

| OWASP Risk | Mitigation |
|-----------|-----------|
| **A01:2021 - Broken Access Control** | ✅ Scope validation, token binding |
| **A02:2021 - Cryptographic Failures** | ✅ Strong algorithms, TLS 1.2+ |
| **A03:2021 - Injection** | ✅ JWT parsing, validation |
| **A04:2021 - Insecure Design** | ✅ Defense in depth, PoP by design |
| **A05:2021 - Security Misconfiguration** | ⚠️ Requires proper configuration |
| **A07:2021 - ID and Auth Failures** | ✅ Strong authentication, MFA |

---

## Security Best Practices

### Developer Guidelines

#### ✅ DO:

1. **Use Hardware Security Modules (HSMs) for private key storage**
   ```csharp
   // Store in Azure Key Vault with HSM backing
   var keyVaultKey = await keyClient.CreateRsaKeyAsync(
       new CreateRsaKeyOptions("pop-key", hardwareProtected: true));
   ```

2. **Implement key rotation**
   ```csharp
   // Rotate keys every 90 days
   await keyRotationService.RotateKeyAsync(TimeSpan.FromDays(90));
   ```

3. **Validate all token claims**
   ```csharp
   // Validate iss, aud, exp, nbf, cnf
   var validationParams = new TokenValidationParameters { /* ... */ };
   ```

4. **Use SN/I mode (not pinned certificates)**
   ```csharp
   var options = new MergedOptions { SendX5C = true };
   ```

5. **Enable token cache encryption**
   ```csharp
   services.AddDistributedTokenCaches();
   ```

---

#### ❌ DON'T:

1. **Don't log access tokens**
   ```csharp
   // ❌ INSECURE
   _logger.LogInformation($"Token: {token.AccessToken}");
   
   // ✅ SECURE
   _logger.LogInformation($"Token acquired, expires: {token.ExpiresOn}");
   ```

2. **Don't use weak key sizes**
   ```csharp
   // ❌ INSECURE: RSA 1024
   var rsa = RSA.Create(1024);
   
   // ✅ SECURE: RSA 2048+
   var rsa = RSA.Create(2048);
   ```

3. **Don't store private keys in source code or config files**
   ```csharp
   // ❌ INSECURE
   var privateKey = "MIIEpAIBAAKCAQEA...";  // Hardcoded
   
   // ✅ SECURE
   var privateKey = await keyVault.GetSecretAsync("pop-private-key");
   ```

4. **Don't disable certificate validation**
   ```csharp
   // ❌ INSECURE
   httpClient.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
   
   // ✅ SECURE
   // Use default certificate validation
   ```

5. **Don't reuse keys across different security contexts**
   ```csharp
   // ❌ INSECURE: Same key for PoP and other purposes
   var key = GetSharedKey();
   
   // ✅ SECURE: Dedicated key for PoP
   var popKey = GetPopKey();
   ```

---

### Operational Security

#### Monitoring and Alerting

```csharp
// Monitor for security anomalies
public class SecurityMonitor
{
    public async Task MonitorTokenUsageAsync()
    {
        // Alert on unusual patterns
        if (tokenRequestRate > threshold)
        {
            await alertService.SendAlertAsync("High token request rate detected");
        }
        
        // Alert on key compromise indicators
        if (multipleClientsSameKey)
        {
            await alertService.SendAlertAsync("Possible key compromise detected");
        }
        
        // Alert on expired certificate usage attempts
        if (expiredCertificateUsage)
        {
            await alertService.SendAlertAsync("Expired certificate usage attempt");
        }
    }
}
```

#### Incident Response

**Key Compromise Response Plan:**

1. **Detect:** Monitor for anomalous key usage patterns
2. **Contain:** Immediately rotate compromised key
3. **Eradicate:** Revoke all tokens bound to compromised key
4. **Recover:** Issue new tokens with new key
5. **Lessons Learned:** Review incident, improve controls

---

### Security Testing

#### Penetration Testing Scenarios

1. **Token Theft Test:**
   - Capture token from network traffic
   - Attempt to use token without private key
   - **Expected Result:** API rejects token (missing PoP proof)

2. **Key Compromise Test:**
   - Simulate key theft
   - Measure detection time
   - **Expected Result:** Automated alerts within SLA

3. **Token Tampering Test:**
   - Modify JWT claims (e.g., extend expiration)
   - **Expected Result:** Signature validation fails

4. **Replay Attack Test:**
   - Replay captured token request
   - **Expected Result:** New token bound to different key

---

## Summary

MSAuth 1.0 AT-POP provides a robust security architecture through:

✅ **Multi-layered defense** (7+ security layers)
✅ **Cryptographic binding** (tokens unusable without private keys)
✅ **Standards compliance** (NIST, OWASP, PCI DSS, HIPAA)
✅ **Threat mitigation** (comprehensive STRIDE coverage)
✅ **Operational controls** (monitoring, rotation, incident response)

**Key Security Takeaways:**

1. **PoP binding is the critical security feature** - prevents token theft
2. **Key storage is the critical attack surface** - use HSMs
3. **Configuration matters** - secure defaults require proper setup
4. **Defense in depth** - multiple controls provide resilience
5. **Continuous monitoring** - detect and respond to threats

---

**Next:** [Token Flow Diagrams](./04-token-flow-diagrams.md)
