# MSAuth 1.0 Protocol Overview

## Executive Summary

**MSAuth 1.0** (Microsoft Authentication Protocol version 1.0) is a proprietary authentication protocol extension developed by Microsoft for the Microsoft Identity Platform. Specifically, the implementation in this repository focuses on **MSAuth 1.0 AT-POP** (Access Token Proof-of-Possession), which represents an advanced security mechanism for OAuth 2.0 access tokens.

### Purpose and Value Proposition

MSAuth 1.0 AT-POP addresses a fundamental security limitation in standard OAuth 2.0 Bearer tokens: **bearer tokens can be stolen and replayed by attackers**. Once an attacker obtains a bearer token, they can use it to access protected resources until the token expires, regardless of who presents it.

MSAuth 1.0 AT-POP solves this problem by:
1. **Cryptographically binding** the access token to a specific client instance
2. **Requiring proof** that the client possesses a private key corresponding to a public key
3. **Preventing token theft/replay** even if the token is intercepted during transmission

### Protocol Classification

- **Type**: OAuth 2.0 Extension / Enhancement
- **Layer**: Token Security Enhancement (sits on top of OAuth 2.0)
- **Security Model**: Proof-of-Possession (PoP)
- **Primary Use Case**: High-security client-to-API authentication
- **Transport**: HTTPS (required)

---

## Protocol Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    MSAuth 1.0 AT-POP Architecture                │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  Client App      │          │  Azure AD        │          │  Protected API   │
│  (Confidential)  │          │  (eSTS)          │          │  (Resource)      │
└────────┬─────────┘          └────────┬─────────┘          └────────┬─────────┘
         │                              │                              │
         │ 1. Generate Key Pair         │                              │
         │    (Asymmetric Crypto)       │                              │
         │◄─────────────────────────────┤                              │
         │                              │                              │
         │ 2. Token Request             │                              │
         │    + req_cnf (public key)    │                              │
         │    + token_type=pop           │                              │
         │    + client_assertion         │                              │
         │─────────────────────────────►│                              │
         │                              │                              │
         │                              │ 3. Validate & Bind           │
         │                              │    Token to Key              │
         │                              │                              │
         │ 4. PoP Access Token          │                              │
         │    (bound to public key)     │                              │
         │◄─────────────────────────────┤                              │
         │                              │                              │
         │ 5. API Request               │                              │
         │    + PoP Token               │                              │
         │    + Signature (private key) │                              │
         │──────────────────────────────┼─────────────────────────────►│
         │                              │                              │
         │                              │                              │ 6. Validate
         │                              │                              │    - Token
         │                              │                              │    - Signature
         │                              │                              │    - Key Match
         │                              │                              │
         │ 7. Protected Resource        │                              │
         │◄─────────────────────────────┼──────────────────────────────┤
         │                              │                              │
```

---

## Core Protocol Elements

### 1. Token Type: `pop`

Unlike standard OAuth 2.0 bearer tokens (`token_type=Bearer`), MSAuth 1.0 uses **Proof-of-Possession tokens** (`token_type=pop`).

**Key Differences:**

| Aspect | Bearer Token | PoP Token (MSAuth 1.0) |
|--------|--------------|------------------------|
| **Security Model** | "Anyone who has the token can use it" | "Only the key holder can use the token" |
| **Token Binding** | None | Cryptographically bound to client's public key |
| **Theft Protection** | ❌ Vulnerable to token theft | ✅ Protected - token useless without private key |
| **Network Interception** | ❌ High risk if intercepted | ✅ Low risk - requires key possession |
| **Replay Protection** | ❌ Can be replayed until expiry | ✅ Cannot be replayed without key |
| **Client Authentication** | Token only | Token + Cryptographic proof |

### 2. Request Confirmation Parameter: `req_cnf`

The `req_cnf` (request confirmation) parameter is a **base64url-encoded JSON Web Key (JWK)** that contains the client's public key.

**Purpose:**
- Communicates the client's public key to the authorization server
- Allows the server to bind the issued token to this specific key
- Enables later verification that the client possesses the corresponding private key

**Format:**
```http
POST /oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

client_id={client-id}
&client_assertion={jwt-assertion}
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&scope=https://graph.microsoft.com/.default
&grant_type=client_credentials
&req_cnf=eyJraWQiOiIxZTlnZGs3IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMHZ4...
&token_type=pop
```

**JWK Structure (decoded req_cnf):**
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "kid": "key-identifier-123",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78...",
  "alg": "RS256"
}
```

### 3. Authentication Operation: `AtPopOperation`

The `AtPopOperation` class implements the `IAuthenticationOperation` interface from MSAL (Microsoft Authentication Library) to customize token acquisition behavior.

**Implementation Location:** `src/Microsoft.Identity.Web.TokenAcquisition/AtPopOperation.cs`

**Key Responsibilities:**
1. **Token Type Declaration**: Specifies `token_type=pop`
2. **Request Parameter Injection**: Adds `req_cnf` parameter to token request
3. **Telemetry**: Reports PoP token type (telemetry code: 4)
4. **Authorization Header**: Uses standard `Bearer` prefix (despite being PoP token)

---

## Protocol Flow: Step-by-Step

### Phase 1: Key Generation (Client-Side)

**Step 1a: Generate Asymmetric Key Pair**

The client application generates an asymmetric cryptographic key pair (typically RSA 2048-bit or higher).

```csharp
// Conceptual representation (actual implementation may vary)
using var rsa = RSA.Create(2048);
RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false);
RSAParameters privateKey = rsa.ExportParameters(includePrivateParameters: true);
```

**Step 1b: Extract Public Key as JWK**

The public key is converted to JSON Web Key (JWK) format:

```json
{
  "kty": "RSA",
  "e": "AQAB",  // Public exponent (typically 65537)
  "n": "0vx7agoebGcQSuuPiLJXZptN...",  // Modulus (base64url-encoded)
  "kid": "unique-key-identifier",
  "alg": "RS256"
}
```

**Step 1c: Prepare Key Identifier**

A unique key identifier (`kid`) is generated or assigned to reference this key pair.

---

### Phase 2: Token Request (Client → Azure AD)

**Step 2a: Build Token Request**

The client constructs an OAuth 2.0 token request with MSAuth 1.0 extensions:

```http
POST /oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=12345678-1234-1234-1234-123456789abc
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&scope=https://graph.microsoft.com/.default
&req_cnf=eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOi4uLg==
&token_type=pop
```

**Critical Parameters:**

| Parameter | Description | MSAuth 1.0 Specific |
|-----------|-------------|---------------------|
| `grant_type` | OAuth 2.0 grant type (e.g., `client_credentials`) | ❌ Standard OAuth 2.0 |
| `client_id` | Application (client) identifier | ❌ Standard OAuth 2.0 |
| `client_assertion` | JWT signed by client certificate (for confidential clients) | ❌ Standard OAuth 2.0 |
| `client_assertion_type` | Format of client_assertion | ❌ Standard OAuth 2.0 |
| `scope` | Requested permissions | ❌ Standard OAuth 2.0 |
| **`req_cnf`** | **Base64url-encoded JWK (public key)** | ✅ **MSAuth 1.0** |
| **`token_type`** | **Must be "pop"** | ✅ **MSAuth 1.0** |

**Step 2b: Client Assertion (for Confidential Clients)**

The `client_assertion` is a JWT signed by the client's certificate (separate from the PoP key):

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5t": "certificate-thumbprint"
}.
{
  "aud": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
  "iss": "12345678-1234-1234-1234-123456789abc",
  "sub": "12345678-1234-1234-1234-123456789abc",
  "jti": "unique-jwt-id",
  "nbf": 1640000000,
  "exp": 1640003600
}.
[Signature]
```

**Important Distinction:**
- **Client Assertion Key**: Authenticates the *client application* to Azure AD
- **PoP Key (req_cnf)**: Binds the *access token* to this specific instance/session

---

### Phase 3: Token Issuance (Azure AD Processing)

**Step 3a: Azure AD Validates Request**

Azure AD (specifically, the Enhanced Security Token Service - eSTS) performs validations:

1. ✅ **Client Identity**: Validates `client_assertion` signature using registered certificate
2. ✅ **Scope Authorization**: Checks if client is authorized for requested scopes
3. ✅ **PoP Parameters**: Validates `req_cnf` format and `token_type=pop`

**Step 3b: Token Binding**

Azure AD binds the access token to the provided public key by including a `cnf` (confirmation) claim in the token:

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
  "iat": 1640000000,
  "nbf": 1640000000,
  "exp": 1640003600,
  "sub": "12345678-1234-1234-1234-123456789abc",
  "cnf": {
    "kid": "unique-key-identifier"
  },
  "scp": "User.Read Mail.Read",
  "token_type": "pop"
}
```

**Step 3c: Token Response**

Azure AD returns the PoP access token:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token_type": "pop",
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "ext_expires_in": 3600
}
```

---

### Phase 4: API Request with PoP Token (Client → API)

**Step 4a: Construct Request**

The client makes an API request with the PoP token:

```http
GET /v1.0/me HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Note:** Despite being a PoP token, the `Authorization` header still uses the `Bearer` scheme for compatibility with existing infrastructure.

**Step 4b: Generate Proof (Future Enhancement)**

In a fully implemented PoP system, the client would generate a signature over the request using the private key:

```
Signature = Sign(PrivateKey, Hash(Method + URL + Headers + Body + Nonce))
```

This signature would be included in a custom header (e.g., `PoP-Signature` or as part of a signed HTTP request).

---

### Phase 5: Token Validation (API/Resource Server)

**Step 5a: Standard Token Validation**

The API validates the access token:

1. ✅ **Signature**: Verifies JWT signature using Azure AD's public keys
2. ✅ **Issuer**: Confirms `iss` claim matches expected Azure AD tenant
3. ✅ **Audience**: Confirms `aud` claim matches API's identifier
4. ✅ **Expiration**: Checks `exp` claim is not in the past
5. ✅ **Not Before**: Checks `nbf` claim is not in the future

**Step 5b: PoP-Specific Validation**

For PoP tokens, additional validation occurs:

1. ✅ **Token Type**: Verifies `token_type=pop` in token claims
2. ✅ **Key Confirmation**: Extracts `cnf` claim with key identifier
3. ✅ **Proof Verification** (if implemented): Validates signature using public key from `cnf`

**Step 5c: Authorization Decision**

If all validations pass, the API grants access to the requested resource.

---

## Security Properties

### Threat Model & Protections

| Threat | Bearer Token | MSAuth 1.0 PoP Token |
|--------|--------------|---------------------|
| **Token Theft (Network Interception)** | ❌ High Risk: Token can be used by attacker | ✅ Protected: Token requires private key |
| **Token Theft (Compromised Storage)** | ❌ High Risk: Stolen token is fully usable | ✅ Protected: Token useless without key |
| **Replay Attacks** | ❌ Vulnerable until token expires | ✅ Mitigated: Requires proof of key possession |
| **Man-in-the-Middle** | ❌ Requires HTTPS; token exposed in transit | ✅ Better: Token binding reduces impact |
| **Token Leakage (Logs/Monitoring)** | ❌ High Risk: Logged token is exploitable | ✅ Reduced Risk: Key still required |
| **Cross-Site Request Forgery (CSRF)** | ❌ Vulnerable if token in cookie | ✅ Protected: Cryptographic binding |

### Cryptographic Guarantees

1. **Authentication**: Proves the client possesses the private key
2. **Integrity**: Token cannot be modified without detection
3. **Non-Repudiation**: Client cannot deny having made the request
4. **Forward Secrecy**: (If implemented with ephemeral keys) Compromise of long-term keys doesn't expose past sessions

### Defense in Depth

MSAuth 1.0 PoP implements multiple security layers:

```
Layer 1: Transport Security (TLS 1.2+)
         ↓
Layer 2: Client Authentication (client_assertion with certificate)
         ↓
Layer 3: Token Binding (cnf claim with public key)
         ↓
Layer 4: Proof of Possession (signature verification)
         ↓
Layer 5: Authorization (scope/role validation)
```

---

## Implementation Modes

### Mode 1: SN/I (Subject Name / Issuer)

**Description:** The recommended approach that uses Subject Name and Issuer from the X.509 certificate.

**Configuration:**
```csharp
// When mergedOptions.SendX5C == true
builder.WithAtPop(popPublicKey, jwkClaim);
```

**Advantages:**
- ✅ More flexible certificate management
- ✅ Supports certificate rotation without code changes
- ✅ Standard X.509 certificate handling
- ✅ Recommended by Microsoft

**Use Case:** Production environments with proper PKI infrastructure

---

### Mode 2: Pinned Certificate (Deprecated)

**Description:** Uses a specific pinned certificate for token binding.

**Configuration:**
```csharp
// When mergedOptions.SendX5C == false
builder.WithAtPop(popPublicKey, jwkClaim);
// Warning logged: "MSAuth POP configured with pinned certificate. 
//                  This configuration is being deprecated."
```

**Disadvantages:**
- ⚠️ Being deprecated by Microsoft
- ⚠️ Requires code changes for certificate rotation
- ⚠️ Less flexible for operational management

**Use Case:** Legacy systems (migration to SN/I recommended)

---

## Protocol Standards & References

### Related RFCs and Specifications

1. **RFC 7800** - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)
   - Defines the `cnf` (confirmation) claim
   - Specifies how to represent cryptographic keys in JWTs

2. **RFC 7638** - JSON Web Key (JWK) Thumbprint
   - Defines how to calculate unique identifiers for JWKs
   - Used for `kid` (key ID) generation

3. **RFC 7517** - JSON Web Key (JWK)
   - Defines the JWK format used in `req_cnf`
   - Specifies key parameters for RSA, ECDSA, etc.

4. **RFC 6749** - OAuth 2.0 Authorization Framework
   - Base protocol that MSAuth 1.0 extends
   - Defines `grant_type`, `scope`, `access_token`, etc.

5. **RFC 7521** - Assertion Framework for OAuth 2.0 Client Authentication
   - Defines `client_assertion` mechanism
   - Used for confidential client authentication

### Microsoft-Specific Documentation

- **Microsoft Identity Platform**: OAuth 2.0 client credentials flow
- **MSAL.NET**: Microsoft Authentication Library for .NET
- **Azure AD Token Reference**: Access token claims and format

---

## Comparison with Other PoP Mechanisms

### MSAuth 1.0 AT-POP vs. Signed HTTP Requests (SHR)

| Feature | MSAuth 1.0 AT-POP | Signed HTTP Requests |
|---------|-------------------|---------------------|
| **Token Binding** | ✅ Yes (cnf claim) | ✅ Yes |
| **Request Signing** | ⚠️ Partial (token request only) | ✅ Yes (every API request) |
| **Complexity** | 🟢 Lower | 🟡 Higher |
| **Security Level** | 🟡 Good | 🟢 Excellent |
| **Compatibility** | 🟢 High (standard Authorization header) | 🟡 Lower (requires custom headers) |
| **Implementation** | `WithAtPop()` | `WithSignedHttpRequestProofOfPossession()` |

**Recommendation:**
- **MSAuth 1.0 AT-POP**: Good balance of security and compatibility
- **Signed HTTP Requests**: Maximum security for high-risk scenarios

---

## Summary

MSAuth 1.0 AT-POP is a robust security enhancement for OAuth 2.0 that:

✅ **Cryptographically binds** access tokens to client keys
✅ **Prevents token theft** by requiring proof of key possession
✅ **Maintains compatibility** with standard OAuth 2.0 infrastructure
✅ **Provides defense in depth** through multiple security layers
✅ **Supports flexible deployment** with SN/I and pinned certificate modes

### When to Use MSAuth 1.0 AT-POP

**Ideal Scenarios:**
- High-security applications (financial services, healthcare, government)
- Confidential clients (server-to-server communication)
- APIs handling sensitive data
- Environments where token theft is a significant risk

**Not Suitable For:**
- Public clients (mobile/SPA apps without secure key storage)
- Low-security requirements where bearer tokens suffice
- Legacy systems incompatible with PoP tokens

---

**Next:** [Technical Implementation Guide](./02-technical-implementation.md)
