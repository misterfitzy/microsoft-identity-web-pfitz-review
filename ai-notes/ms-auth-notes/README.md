# MSAuth 1.0 Protocol Documentation

## Overview

This directory contains comprehensive technical documentation for **MSAuth 1.0 AT-POP** (Access Token Proof-of-Possession), a proprietary authentication protocol extension developed by Microsoft for the Microsoft Identity Platform.

MSAuth 1.0 AT-POP enhances OAuth 2.0 security by cryptographically binding access tokens to client keys, preventing token theft and replay attacks.

---

## Documentation Structure

### 1. [Protocol Overview](./01-msauth10-overview.md)

**Target Audience:** Architects, security engineers, protocol engineers

**Contents:**
- Executive summary and value proposition
- Protocol architecture and components
- Core protocol elements (`token_type=pop`, `req_cnf`, `AtPopOperation`)
- Complete protocol flow (5 phases)
- Security properties and threat model comparison
- Implementation modes (SN/I vs. pinned certificate)
- Standards and RFC references
- Comparison with other PoP mechanisms

**Key Takeaway:** Understanding the "why" and "what" of MSAuth 1.0 AT-POP

---

### 2. [Technical Implementation Guide](./02-technical-implementation.md)

**Target Audience:** Software engineers, developers

**Contents:**
- Architecture overview with component diagrams
- Complete source code walkthrough
  - `MsAuth10AtPop.cs` (extension method)
  - `AtPopOperation.cs` (operation implementation)
  - `TokenAcquisition.cs` (integration)
- Code analysis and implementation details
- MSAL.NET integration patterns
- Configuration options
- Testing strategies (unit tests, integration tests)
- Troubleshooting guide
- Advanced topics (custom key storage, key rotation)

**Key Takeaway:** Understanding the "how" - implementing MSAuth 1.0 in code

---

### 3. [Security Architecture](./03-security-architecture.md)

**Target Audience:** Security engineers, compliance officers, architects

**Contents:**
- Security model overview (defense in depth)
- Comprehensive threat analysis (STRIDE methodology)
  - Spoofing identity
  - Tampering
  - Repudiation
  - Information disclosure
  - Denial of service
  - Elevation of privilege
- Cryptographic foundations
  - Asymmetric key cryptography
  - Supported algorithms and key sizes
  - JWT security properties
- Attack surface analysis with mitigations
- Security controls matrix
- Compliance and standards (PCI DSS, HIPAA, NIST, OWASP)
- Security best practices and operational security

**Key Takeaway:** Understanding the security guarantees and how to maintain them

---

### 4. [Token Flow Diagrams and Specifications](./04-token-flow-diagrams.md)

**Target Audience:** Protocol engineers, architects, developers

**Contents:**
- Complete end-to-end protocol flow diagram
- Detailed message sequence diagrams
  - Token acquisition flow
  - `WithAtPop` extension method flow
  - Error handling flow
- State transition diagrams
  - Token lifecycle state machine
  - Client authentication states
- Complete token structure specifications
  - MSAuth 1.0 PoP access token (JWT)
  - Client assertion JWT
  - Request confirmation parameter (req_cnf)
- API request/response examples with actual HTTP messages
- Error flows with common scenarios

**Key Takeaway:** Visual and structural understanding of the protocol

---

### 5. [Integration Guide and Best Practices](./05-integration-guide.md)

**Target Audience:** Software engineers, DevOps engineers, architects

**Contents:**
- Quick start guide (5-minute integration)
- Step-by-step integration
  - Azure AD application registration
  - .NET application setup
  - PoP key management (in-memory vs. Azure Key Vault)
  - Dependency injection configuration
  - Token acquisition and usage
- Configuration patterns
  - Azure Key Vault integration
  - SN/I mode configuration
  - Multi-tenant configuration
- Best practices
  - Security (HSMs, key rotation, no logging secrets)
  - Performance (caching, circuit breakers, parallel calls)
- Production considerations
  - Monitoring and observability
  - Health checks
- Common pitfalls and solutions
- Migration guide (Bearer → PoP tokens)

**Key Takeaway:** Practical, production-ready implementation patterns

---

## Quick Reference

### What is MSAuth 1.0 AT-POP?

MSAuth 1.0 AT-POP is an OAuth 2.0 extension that:
- **Binds** access tokens to client keys using proof-of-possession
- **Prevents** token theft and replay attacks
- **Requires** cryptographic proof of key possession to use tokens
- **Maintains** compatibility with existing OAuth 2.0 infrastructure

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Extension Method** | `MsAuth10AtPop.cs` | Enables PoP on MSAL token builders |
| **Operation Class** | `AtPopOperation.cs` | Implements MSAL `IAuthenticationOperation` |
| **Integration** | `TokenAcquisition.cs` | Integrates PoP into token acquisition |

### Key Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **PopPublicKey** | Key identifier (kid) | `"key-abc-123"` |
| **PopClaim** | JWK as JSON string | `"{\"kty\":\"RSA\",\"e\":\"AQAB\",...}"` |
| **req_cnf** | Base64URL-encoded JWK | `"eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsLi4ufQ"` |
| **token_type** | Token type | `"pop"` |

### Protocol Flow (High-Level)

```
1. Client generates RSA key pair (2048-bit+)
2. Client sends token request with:
   - req_cnf (base64url-encoded public key JWK)
   - token_type=pop
   - client_assertion (certificate-based auth)
3. Azure AD validates request and creates PoP token with cnf claim
4. Client uses PoP token to call APIs (requires private key)
5. API validates token and PoP binding
```

---

## Implementation Checklist

### Prerequisites
- [ ] Azure AD tenant and application registration
- [ ] Client certificate for application authentication
- [ ] .NET 6.0+ with Microsoft.Identity.Web 2.5.0+
- [ ] Understanding of OAuth 2.0 and JWT

### Development
- [ ] Install NuGet packages (`Microsoft.Identity.Web`)
- [ ] Configure Azure AD settings in `appsettings.json`
- [ ] Implement PoP key storage (in-memory for dev/testing)
- [ ] Configure MSAL with `.WithExperimentalFeatures()`
- [ ] Acquire tokens using `.WithAtPop(keyId, jwk)`
- [ ] Test with unit and integration tests

### Production
- [ ] Migrate to Azure Key Vault for key storage
- [ ] Enable HSM-backed keys
- [ ] Configure SN/I mode (`SendX5C = true`)
- [ ] Implement key rotation (90-day cycle)
- [ ] Set up distributed token cache
- [ ] Configure monitoring and alerting
- [ ] Implement health checks
- [ ] Review and follow security best practices
- [ ] Test disaster recovery procedures

---

## Security Considerations

### Critical Security Controls

| Control | Implementation | Criticality |
|---------|----------------|-------------|
| **Private Key Protection** | Store in HSM (Azure Key Vault) | 🔴 Critical |
| **Key Rotation** | Automated 90-day rotation | 🟡 High |
| **Token Cache Encryption** | Distributed cache with encryption | 🟡 High |
| **No Logging Secrets** | Never log tokens/keys/JWKs | 🔴 Critical |
| **TLS 1.2+** | Enforce HTTPS with strong ciphers | 🔴 Critical |

### Threat Mitigation

| Threat | Bearer Token Risk | MSAuth 1.0 PoP Risk |
|--------|------------------|---------------------|
| Token Theft | 🔴 High | 🟢 Low |
| Replay Attacks | 🔴 High | 🟢 Low |
| MITM | 🟡 Medium | 🟢 Low |
| Key Compromise | N/A | 🟡 Medium |

---

## Common Use Cases

### When to Use MSAuth 1.0 AT-POP

✅ **Ideal for:**
- High-security applications (financial, healthcare, government)
- Confidential clients (server-to-server)
- APIs handling sensitive data
- Environments with high token theft risk

❌ **Not suitable for:**
- Public clients (mobile/SPA without secure key storage)
- Low-security requirements
- Legacy systems incompatible with PoP

---

## Troubleshooting

### Common Issues

| Issue | Solution | Reference |
|-------|----------|-----------|
| "Experimental features not enabled" | Add `.WithExperimentalFeatures()` | [Implementation Guide](./02-technical-implementation.md#troubleshooting) |
| "ArgumentException: popPublicKey null" | Set `PopPublicKey` in options | [Implementation Guide](./02-technical-implementation.md#troubleshooting) |
| "Token type mismatch" | Verify Azure AD PoP support | [Implementation Guide](./02-technical-implementation.md#troubleshooting) |
| "Deprecated pinned cert warning" | Migrate to SN/I mode | [Integration Guide](./05-integration-guide.md#configuration-patterns) |

---

## Additional Resources

### Microsoft Documentation
- [Microsoft Identity Platform](https://learn.microsoft.com/azure/active-directory/develop/)
- [Microsoft.Identity.Web GitHub](https://github.com/AzureAD/microsoft-identity-web)
- [MSAL.NET Documentation](https://learn.microsoft.com/azure/active-directory/develop/msal-overview)

### Standards and RFCs
- [RFC 7800: Proof-of-Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800.html)
- [RFC 7517: JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517.html)
- [RFC 6749: OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html)

### Community Support
- [GitHub Issues](https://github.com/AzureAD/microsoft-identity-web/issues)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/microsoft-identity-web)

---

## Document Versions

| Document | Version | Last Updated | Author |
|----------|---------|--------------|--------|
| 01-msauth10-overview.md | 1.0 | 2024 | AI Protocol Review |
| 02-technical-implementation.md | 1.0 | 2024 | AI Protocol Review |
| 03-security-architecture.md | 1.0 | 2024 | AI Protocol Review |
| 04-token-flow-diagrams.md | 1.0 | 2024 | AI Protocol Review |
| 05-integration-guide.md | 1.0 | 2024 | AI Protocol Review |

---

## Feedback and Contributions

This documentation was created as part of a comprehensive protocol review. For:
- **Corrections or updates**: Open an issue in the repository
- **Questions**: Use Stack Overflow with tag `microsoft-identity-web`
- **Security concerns**: Report to secure@microsoft.com

---

**Navigation:**
- [← Back to AI Notes](../README.md)
- [Protocol Overview →](./01-msauth10-overview.md)
