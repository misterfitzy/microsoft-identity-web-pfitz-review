// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AuthScheme;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.IdentityModel.Tokens;

namespace MSAuth10PocApp;

/// <summary>
/// Extension method to enable MSAuth 1.0 AT-POP on MSAL token acquisition.
/// This is a copy of the internal implementation for demonstration purposes.
/// </summary>
internal static class MsAuth10AtPopExtensions
{
    internal static AcquireTokenForClientParameterBuilder WithAtPop(
        this AcquireTokenForClientParameterBuilder builder,
        string popPublicKey,
        string jwkClaim)
    {
        if (string.IsNullOrWhiteSpace(popPublicKey))
            throw new ArgumentException("PoP public key cannot be null or whitespace", nameof(popPublicKey));
        
        if (string.IsNullOrWhiteSpace(jwkClaim))
            throw new ArgumentException("JWK claim cannot be null or whitespace", nameof(jwkClaim));

        var op = new AtPopOperation(popPublicKey, jwkClaim);
        builder.WithAuthenticationExtension(new MsalAuthenticationExtension()
        {
            AuthenticationOperation = op
        });
        return builder;
    }
}

/// <summary>
/// Implements the IAuthenticationOperation interface to customize MSAL token requests for MSAuth 1.0 AT-POP.
/// This is a copy of the internal implementation for demonstration purposes.
/// </summary>
internal class AtPopOperation : IAuthenticationOperation
{
    private readonly string _reqCnf;

    public AtPopOperation(string keyId, string reqCnf)
    {
        KeyId = keyId;
        _reqCnf = reqCnf;
    }

    public int TelemetryTokenType => 4; // as per TelemetryTokenTypeConstants

    public string AuthorizationHeaderPrefix => "Bearer"; // these tokens go over bearer

    public string KeyId { get; }

    public string AccessTokenType => "pop"; // eSTS returns token_type=pop and MSAL needs to know

    public void FormatResult(AuthenticationResult authenticationResult)
    {
        // no-op, adding the SHR is done by the caller
    }

    public IReadOnlyDictionary<string, string> GetTokenRequestParams()
    {
        return new Dictionary<string, string>()
        {
            {"req_cnf", Base64UrlEncoder.Encode(_reqCnf) },
            {"token_type", "pop" }
        };
    }
}
