# MSAuth 1.0 Token Flow Diagrams and Specifications

## Table of Contents

1. [Complete Protocol Flow](#complete-protocol-flow)
2. [Message Sequence Diagrams](#message-sequence-diagrams)
3. [State Transition Diagrams](#state-transition-diagrams)
4. [Token Structure Specifications](#token-structure-specifications)
5. [API Request/Response Examples](#api-request-response-examples)
6. [Error Flows](#error-flows)

---

## Complete Protocol Flow

### End-to-End MSAuth 1.0 AT-POP Flow

```
┌──────────────┐                 ┌──────────────┐                 ┌──────────────┐
│   Client     │                 │  Azure AD    │                 │  Resource    │
│ Application  │                 │   (eSTS)     │                 │     API      │
└──────┬───────┘                 └──────┬───────┘                 └──────┬───────┘
       │                                │                                │
       │ ┌──────────────────────────────────────────────────────────┐   │
       │ │ Phase 1: Key Generation (Client-Side)                    │   │
       │ └──────────────────────────────────────────────────────────┘   │
       │                                │                                │
       │ 1a. Generate RSA Key Pair      │                                │
       │     (2048-bit or higher)       │                                │
       │◄────────────────────────       │                                │
       │                                │                                │
       │ 1b. Extract Public Key (JWK)   │                                │
       │◄────────────────────────       │                                │
       │                                │                                │
       │ 1c. Create Key Identifier      │                                │
       │◄────────────────────────       │                                │
       │                                │                                │
       │ ┌──────────────────────────────────────────────────────────┐   │
       │ │ Phase 2: Token Request                                   │   │
       │ └──────────────────────────────────────────────────────────┘   │
       │                                │                                │
       │ 2a. Build Client Assertion     │                                │
       │     (JWT signed with cert)     │                                │
       │◄────────────────────────       │                                │
       │                                │                                │
       │ 2b. POST /oauth2/v2.0/token    │                                │
       │     + grant_type=client_creds  │                                │
       │     + client_assertion         │                                │
       │     + req_cnf (base64url JWK)  │                                │
       │     + token_type=pop            │                                │
       │─────────────────────────────────►                                │
       │                                │                                │
       │ ┌──────────────────────────────────────────────────────────┐   │
       │ │ Phase 3: Token Issuance (Azure AD)                       │   │
       │ └──────────────────────────────────────────────────────────┘   │
       │                                │                                │
       │                                │ 3a. Validate client_assertion  │
       │                                │◄────────────────────────       │
       │                                │                                │
       │                                │ 3b. Validate req_cnf format    │
       │                                │◄────────────────────────       │
       │                                │                                │
       │                                │ 3c. Create PoP Access Token    │
       │                                │     with cnf claim             │
       │                                │◄────────────────────────       │
       │                                │                                │
       │ 3d. 200 OK                     │                                │
       │     {                          │                                │
       │       "token_type": "pop",     │                                │
       │       "access_token": "...",   │                                │
       │       "expires_in": 3600       │                                │
       │     }                          │                                │
       │◄─────────────────────────────────                                │
       │                                │                                │
       │ ┌──────────────────────────────────────────────────────────┐   │
       │ │ Phase 4: API Request with PoP Token                      │   │
       │ └──────────────────────────────────────────────────────────┘   │
       │                                │                                │
       │ 4a. GET /api/resource          │                                │
       │     Authorization: Bearer {token}                               │
       │─────────────────────────────────┼────────────────────────────────►
       │                                │                                │
       │ ┌──────────────────────────────────────────────────────────┐   │
       │ │ Phase 5: Token Validation (API)                          │   │
       │ └──────────────────────────────────────────────────────────┘   │
       │                                │                                │
       │                                │                                │ 5a. Validate JWT signature
       │                                │                                │◄────────────────────
       │                                │                                │
       │                                │                                │ 5b. Validate iss, aud, exp
       │                                │                                │◄────────────────────
       │                                │                                │
       │                                │                                │ 5c. Verify token_type=pop
       │                                │                                │◄────────────────────
       │                                │                                │
       │                                │                                │ 5d. Extract cnf claim
       │                                │                                │◄────────────────────
       │                                │                                │
       │ 5e. 200 OK                     │                                │
       │     { "data": "..." }          │                                │
       │◄────────────────────────────────┼────────────────────────────────┤
       │                                │                                │
```

---

## Message Sequence Diagrams

### Diagram 1: Token Acquisition Flow (Detailed)

```
Client App          MSAL.NET          Azure AD          Token Cache
    │                  │                  │                  │
    │ GetAccessToken   │                  │                  │
    │─────────────────►│                  │                  │
    │                  │                  │                  │
    │                  │ Check Cache      │                  │
    │                  │─────────────────────────────────────►│
    │                  │                  │                  │
    │                  │ Cache Miss       │                  │
    │                  │◄─────────────────────────────────────┤
    │                  │                  │                  │
    │                  │ Build Request    │                  │
    │                  │ - GetTokenRequestParams()           │
    │                  │   returns {req_cnf, token_type}     │
    │                  │◄─────────────    │                  │
    │                  │                  │                  │
    │                  │ POST /token      │                  │
    │                  │ + client_id      │                  │
    │                  │ + client_assertion                  │
    │                  │ + req_cnf        │                  │
    │                  │ + token_type=pop │                  │
    │                  │ + scope          │                  │
    │                  │──────────────────►                  │
    │                  │                  │                  │
    │                  │                  │ Validate Request │
    │                  │                  │ - client_assertion
    │                  │                  │ - req_cnf format │
    │                  │                  │◄─────────────    │
    │                  │                  │                  │
    │                  │                  │ Create Token     │
    │                  │                  │ - Add cnf claim  │
    │                  │                  │ - token_type=pop │
    │                  │                  │◄─────────────    │
    │                  │                  │                  │
    │                  │ 200 OK           │                  │
    │                  │ {token_type,     │                  │
    │                  │  access_token,   │                  │
    │                  │  expires_in}     │                  │
    │                  │◄──────────────────                  │
    │                  │                  │                  │
    │                  │ Validate token_type=pop             │
    │                  │◄─────────────    │                  │
    │                  │                  │                  │
    │                  │ Cache Token      │                  │
    │                  │─────────────────────────────────────►│
    │                  │                  │                  │
    │ AccessToken      │                  │                  │
    │◄─────────────────┤                  │                  │
    │                  │                  │                  │
```

---

### Diagram 2: WithAtPop Extension Method Flow

```
Application Code          MsAuth10AtPop         AtPopOperation         MSAL Builder
      │                        │                       │                      │
      │ AcquireTokenForClient  │                       │                      │
      │────────────────────────┼───────────────────────┼─────────────────────►│
      │                        │                       │                      │
      │ WithAtPop(keyId, jwk)  │                       │                      │
      │───────────────────────►│                       │                      │
      │                        │                       │                      │
      │                        │ Validate Parameters   │                      │
      │                        │ - Throws.IfNullOrWhitespace(keyId)           │
      │                        │ - Throws.IfNullOrWhitespace(jwk)             │
      │                        │◄──────────────        │                      │
      │                        │                       │                      │
      │                        │ new AtPopOperation(   │                      │
      │                        │    keyId, jwk)        │                      │
      │                        │──────────────────────►│                      │
      │                        │                       │                      │
      │                        │                       │ Store keyId, jwk     │
      │                        │                       │◄─────────────        │
      │                        │                       │                      │
      │                        │ WithAuthenticationExtension(                 │
      │                        │    new MsalAuthenticationExtension {         │
      │                        │      AuthenticationOperation = op })         │
      │                        │──────────────────────────────────────────────►│
      │                        │                       │                      │
      │                        │                       │                      │ Register Operation
      │                        │                       │                      │◄─────────────
      │                        │                       │                      │
      │ Builder (modified)     │                       │                      │
      │◄───────────────────────┤                       │                      │
      │                        │                       │                      │
      │ ExecuteAsync()         │                       │                      │
      │────────────────────────┼───────────────────────┼─────────────────────►│
      │                        │                       │                      │
      │                        │                       │                      │ Call GetTokenRequestParams()
      │                        │                       │                      │───────────────────────►│
      │                        │                       │                      │                        │
      │                        │                       │ Return {req_cnf,     │                        │
      │                        │                       │         token_type}  │                        │
      │                        │                       │◄──────────────────────                        │
      │                        │                       │                      │                        │
      │                        │                       │                      │ Add to HTTP Request    │
      │                        │                       │                      │◄─────────────          │
      │                        │                       │                      │                        │
```

---

### Diagram 3: Error Handling Flow

```
Client              MSAL             Azure AD
  │                  │                  │
  │ AcquireToken     │                  │
  │─────────────────►│                  │
  │                  │                  │
  │                  │ POST /token      │
  │                  │ (invalid req_cnf)│
  │                  │──────────────────►│
  │                  │                  │
  │                  │                  │ Validate req_cnf
  │                  │                  │◄─────────────
  │                  │                  │ Invalid format!
  │                  │                  │
  │                  │ 400 Bad Request  │
  │                  │ {                │
  │                  │   "error": "invalid_request",
  │                  │   "error_description": "req_cnf format invalid"
  │                  │ }                │
  │                  │◄──────────────────│
  │                  │                  │
  │ MsalServiceException                │
  │ - ErrorCode: invalid_request        │
  │ - Message: "req_cnf format invalid" │
  │◄─────────────────┤                  │
  │                  │                  │
  │ Log Error        │                  │
  │ Retry with       │                  │
  │ corrected req_cnf│                  │
  │◄─────────────    │                  │
  │                  │                  │
```

---

## State Transition Diagrams

### Token Lifecycle State Machine

```
┌────────────────────────────────────────────────────────────────┐
│                   Token State Transitions                       │
└────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │  NOT_EXIST  │  (No token acquired yet)
    └──────┬──────┘
           │
           │ AcquireTokenForClient().WithAtPop().ExecuteAsync()
           ▼
    ┌─────────────┐
    │  REQUESTED  │  (HTTP request in flight)
    └──────┬──────┘
           │
           │ Azure AD validates request
           │
           ├─────────── Success ───────►┌─────────────┐
           │                            │    VALID    │  (Token usable)
           │                            └──────┬──────┘
           │                                   │
           │                                   │ Time passes
           │                                   │ (exp claim reached)
           │                                   ▼
           │                            ┌─────────────┐
           │                            │   EXPIRED   │  (Token unusable)
           │                            └──────┬──────┘
           │                                   │
           │                                   │ Token refresh/reacquire
           │                                   │
           │                                   └──────────────┐
           │                                                  │
           └─────────── Failure ────────►┌─────────────┐     │
                                         │   ERROR     │     │
                                         └──────┬──────┘     │
                                                │            │
                                                │ Retry      │
                                                └────────────┘

State Descriptions:

NOT_EXIST:  No token in cache, must acquire new token
REQUESTED:  Token request sent to Azure AD, awaiting response
VALID:      Token in cache, not expired, can be used for API calls
EXPIRED:    Token past exp timestamp, must refresh or reacquire
ERROR:      Token acquisition failed, may retry with backoff
```

---

### Client Authentication State Flow

```
┌────────────────────────────────────────────────────────────────┐
│              Client Authentication States                       │
└────────────────────────────────────────────────────────────────┘

    ┌─────────────────┐
    │ UNAUTHENTICATED │
    └────────┬────────┘
             │
             │ Load certificate
             ▼
    ┌─────────────────┐
    │ CERT_LOADED     │
    └────────┬────────┘
             │
             │ Create client_assertion JWT
             ▼
    ┌─────────────────┐
    │ ASSERTION_READY │
    └────────┬────────┘
             │
             │ Send to Azure AD
             ▼
    ┌─────────────────┐
    │ VALIDATING      │
    └────────┬────────┘
             │
             ├── Valid ────────►┌─────────────────┐
             │                  │ AUTHENTICATED   │
             │                  └────────┬────────┘
             │                           │
             │                           │ Cert expires
             │                           ▼
             │                  ┌─────────────────┐
             │                  │ CERT_EXPIRED    │
             │                  └─────────────────┘
             │
             └── Invalid ──────►┌─────────────────┐
                                │ AUTH_FAILED     │
                                └─────────────────┘
```

---

## Token Structure Specifications

### MSAuth 1.0 PoP Access Token (JWT)

#### Complete Token Structure

```json
{
  "header": {
    "alg": "RS256",              // Signing algorithm
    "typ": "JWT",                // Token type
    "kid": "azure-ad-key-123",   // Azure AD's signing key ID
    "x5t": "cert-thumbprint"     // Certificate thumbprint
  },
  "payload": {
    // ===== Standard OAuth 2.0 Claims =====
    "iss": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
    "aud": "https://graph.microsoft.com",
    "exp": 1640003600,           // Expiration time (Unix timestamp)
    "nbf": 1640000000,           // Not before time
    "iat": 1640000000,           // Issued at time
    "jti": "unique-token-id",    // JWT ID (unique identifier)
    
    // ===== Azure AD Specific Claims =====
    "sub": "12345678-1234-1234-1234-123456789abc",  // Subject (client ID)
    "azp": "12345678-1234-1234-1234-123456789abc",  // Authorized party
    "ver": "2.0",                // Token version
    "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",  // Tenant ID
    
    // ===== Scope and Permissions =====
    "scp": "User.Read Mail.Read",              // Scopes (delegated permissions)
    "roles": ["Application.ReadWrite.All"],    // Application roles
    
    // ===== MSAuth 1.0 PoP Claims =====
    "cnf": {                     // *** Confirmation claim (PoP binding) ***
      "kid": "client-pop-key-id" // Client's public key identifier
    },
    
    // ===== Optional Claims =====
    "app_displayname": "My Application",
    "appid": "12345678-1234-1234-1234-123456789abc",
    "idtyp": "app",              // Identity type (app/user)
    "oid": "object-id",          // Object ID
    "rh": "refresh-hint",        // Refresh hint
    "uti": "unique-token-instance",
    "xms_tcdt": 1234567890       // Tenant creation date
  },
  "signature": "..."             // RS256 signature over header.payload
}
```

#### Claim Definitions

| Claim | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| **iss** | string | ✅ Yes | Token issuer (Azure AD) | `https://login.microsoftonline.com/{tenant}/v2.0` |
| **aud** | string | ✅ Yes | Intended audience (resource API) | `https://graph.microsoft.com` |
| **exp** | number | ✅ Yes | Expiration time (Unix timestamp) | `1640003600` |
| **nbf** | number | ✅ Yes | Not before time | `1640000000` |
| **iat** | number | ✅ Yes | Issued at time | `1640000000` |
| **jti** | string | ✅ Yes | Unique token ID | `"unique-token-id"` |
| **sub** | string | ✅ Yes | Subject (client/user ID) | `"12345678-1234..."` |
| **cnf** | object | ✅ Yes (PoP) | **Confirmation claim with key ID** | `{"kid": "key-id"}` |
| **scp** | string | ❌ No | Delegated permission scopes | `"User.Read Mail.Read"` |
| **roles** | array | ❌ No | Application permission roles | `["Application.ReadWrite.All"]` |
| **tid** | string | ✅ Yes | Tenant ID | `"72f988bf-..."` |
| **ver** | string | ✅ Yes | Token version | `"2.0"` |

---

### Client Assertion JWT (client_assertion)

```json
{
  "header": {
    "alg": "RS256",              // Signing algorithm
    "typ": "JWT",                // Token type
    "x5t": "cert-thumbprint",    // Certificate thumbprint (SHA-1)
    "x5c": ["cert-chain"]        // (Optional) Certificate chain
  },
  "payload": {
    "aud": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
    "iss": "12345678-1234-1234-1234-123456789abc",  // Client ID
    "sub": "12345678-1234-1234-1234-123456789abc",  // Client ID
    "jti": "unique-assertion-id",
    "nbf": 1640000000,
    "exp": 1640003600            // Short-lived (typically 10 min)
  },
  "signature": "..."             // Signed with client certificate private key
}
```

**Purpose:** Authenticates the client application to Azure AD using certificate-based authentication.

---

### Request Confirmation Parameter (req_cnf)

**Format:** Base64URL-encoded JSON Web Key (JWK)

**Original JWK (before encoding):**

```json
{
  "kty": "RSA",                  // Key type
  "e": "AQAB",                   // Public exponent (65537)
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV...",
  "alg": "RS256",                // Algorithm
  "kid": "client-pop-key-id"     // Key identifier
}
```

**Base64URL-encoded (sent as req_cnf):**

```
eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIwdng3YWdvZWJHY1FTdXVQaUxKWFpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFYuLi4iLCJhbGciOiJSUzI1NiIsImtpZCI6ImNsaWVudC1wb3Ata2V5LWlkIn0
```

**JWK Parameters:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| **kty** | Key type | `"RSA"` |
| **e** | RSA public exponent (base64url) | `"AQAB"` (65537) |
| **n** | RSA modulus (base64url) | `"0vx7ago..."` |
| **alg** | Algorithm | `"RS256"` |
| **kid** | Key identifier | `"client-pop-key-id"` |

---

## API Request/Response Examples

### Example 1: Successful Token Acquisition

**Request:**

```http
POST /72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Microsoft.Identity.Web/2.5.0

grant_type=client_credentials
&client_id=12345678-1234-1234-1234-123456789abc
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6ImNlcnQtdGh1bWJwcmludCJ9.eyJhdWQiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L29hdXRoMi92Mi4wL3Rva2VuIiwiaXNzIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwic3ViIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwianRpIjoidW5pcXVlLWFzc2VydGlvbi1pZCIsIm5iZiI6MTY0MDAwMDAwMCwiZXhwIjoxNjQwMDAzNjAwfQ.signature
&scope=https://graph.microsoft.com/.default
&req_cnf=eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIwdng3YWdvZWJHY1FTdXVQaUxKWFpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFYuLi4iLCJhbGciOiJSUzI1NiIsImtpZCI6ImNsaWVudC1wb3Ata2V5LWlkIn0
&token_type=pop
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: no-store, no-cache
Pragma: no-cache

{
  "token_type": "pop",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF6dXJlLWFkLWtleS0xMjMiLCJ4NXQiOiJjZXJ0LXRodW1icHJpbnQifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJleHAiOjE2NDAwMDM2MDAsIm5iZiI6MTY0MDAwMDAwMCwiaWF0IjoxNjQwMDAwMDAwLCJqdGkiOiJ1bmlxdWUtdG9rZW4taWQiLCJzdWIiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJhenAiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJ2ZXIiOiIyLjAiLCJ0aWQiOiI3MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDciLCJzY3AiOiJVc2VyLlJlYWQgTWFpbC5SZWFkIiwiY25mIjp7ImtpZCI6ImNsaWVudC1wb3Ata2V5LWlkIn0sImFwcF9kaXNwbGF5bmFtZSI6Ik15IEFwcGxpY2F0aW9uIiwiYXBwaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJpZHR5cCI6ImFwcCIsIm9pZCI6Im9iamVjdC1pZCIsInJoIjoicmVmcmVzaC1oaW50IiwidXRpIjoidW5pcXVlLXRva2VuLWluc3RhbmNlIiwieG1zX3RjZHQiOjEyMzQ1Njc4OTB9.signature"
}
```

---

### Example 2: API Call with PoP Token

**Request:**

```http
GET /v1.0/users HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF6dXJlLWFkLWtleS0xMjMiLCJ4NXQiOiJjZXJ0LXRodW1icHJpbnQifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJleHAiOjE2NDAwMDM2MDAsIm5iZiI6MTY0MDAwMDAwMCwiaWF0IjoxNjQwMDAwMDAwLCJqdGkiOiJ1bmlxdWUtdG9rZW4taWQiLCJzdWIiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJhenAiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJ2ZXIiOiIyLjAiLCJ0aWQiOiI3MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDciLCJzY3AiOiJVc2VyLlJlYWQgTWFpbC5SZWFkIiwiY25mIjp7ImtpZCI6ImNsaWVudC1wb3Ata2V5LWlkIn0sImFwcF9kaXNwbGF5bmFtZSI6Ik15IEFwcGxpY2F0aW9uIiwiYXBwaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJpZHR5cCI6ImFwcCIsIm9pZCI6Im9iamVjdC1pZCIsInJoIjoicmVmcmVzaC1oaW50IiwidXRpIjoidW5pcXVlLXRva2VuLWluc3RhbmNlIiwieG1zX3RjZHQiOjEyMzQ1Njc4OTB9.signature
Accept: application/json
User-Agent: MyApp/1.0
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Request-Id: abc-123-def-456

{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
  "value": [
    {
      "id": "user-id-1",
      "displayName": "John Doe",
      "mail": "john.doe@contoso.com",
      "userPrincipalName": "john.doe@contoso.com"
    },
    {
      "id": "user-id-2",
      "displayName": "Jane Smith",
      "mail": "jane.smith@contoso.com",
      "userPrincipalName": "jane.smith@contoso.com"
    }
  ]
}
```

---

## Error Flows

### Error 1: Invalid req_cnf Format

**Request:**

```http
POST /oauth2/v2.0/token HTTP/1.1
...
req_cnf=invalid-not-base64url-encoded-jwk
token_type=pop
```

**Response:**

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_request",
  "error_description": "AADSTS90000: The request is malformed. Parameter 'req_cnf' is invalid.",
  "error_codes": [90000],
  "timestamp": "2023-12-20 15:30:00Z",
  "trace_id": "abc-123-def-456",
  "correlation_id": "correlation-id-xyz"
}
```

---

### Error 2: Missing token_type Parameter

**Request:**

```http
POST /oauth2/v2.0/token HTTP/1.1
...
req_cnf=eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOi4uLn0
# Missing: token_type=pop
```

**Response:**

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_request",
  "error_description": "AADSTS90001: Required parameter 'token_type' is missing when 'req_cnf' is provided.",
  "error_codes": [90001],
  "timestamp": "2023-12-20 15:30:00Z",
  "trace_id": "abc-123-def-456",
  "correlation_id": "correlation-id-xyz"
}
```

---

### Error 3: Token Type Mismatch

**Scenario:** MSAL expects `token_type=pop` but Azure AD returns `token_type=Bearer`

**MSAL Validation:**

```csharp
// Inside MSAL.NET
if (response.TokenType != operation.AccessTokenType)
{
    throw new MsalServiceException(
        "token_type_mismatch",
        $"Expected token_type '{operation.AccessTokenType}' but received '{response.TokenType}'");
}
```

**Exception:**

```
MsalServiceException: Token type 'Bearer' does not match expected type 'pop'
ErrorCode: token_type_mismatch
```

---

### Error 4: Client Assertion Invalid

**Request:**

```http
POST /oauth2/v2.0/token HTTP/1.1
...
client_assertion=invalid-or-expired-jwt
```

**Response:**

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_client",
  "error_description": "AADSTS700027: Client assertion failed signature validation.",
  "error_codes": [700027],
  "timestamp": "2023-12-20 15:30:00Z",
  "trace_id": "abc-123-def-456",
  "correlation_id": "correlation-id-xyz"
}
```

---

### Error 5: Insufficient Scopes

**Request:**

```http
POST /oauth2/v2.0/token HTTP/1.1
...
scope=https://graph.microsoft.com/.default
# Client not authorized for these scopes
```

**Response:**

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "unauthorized_client",
  "error_description": "AADSTS650051: The application is not authorized to access the requested scopes.",
  "error_codes": [650051],
  "timestamp": "2023-12-20 15:30:00Z",
  "trace_id": "abc-123-def-456",
  "correlation_id": "correlation-id-xyz"
}
```

---

## Summary

This document provides comprehensive specifications for MSAuth 1.0 AT-POP:

✅ **Complete protocol flows** with detailed sequence diagrams
✅ **State transition models** for token lifecycle management
✅ **Token structure specifications** with all claim definitions
✅ **Request/response examples** with actual HTTP messages
✅ **Error handling flows** with common error scenarios

**Key Takeaways:**

1. **req_cnf is base64url-encoded JWK** - must encode properly
2. **token_type=pop is required** - along with req_cnf
3. **cnf claim binds token to key** - critical security feature
4. **client_assertion authenticates client** - separate from PoP
5. **Error handling is comprehensive** - validates at multiple layers

---

**Next:** [Integration Guide and Best Practices](./05-integration-guide.md)
