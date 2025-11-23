// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;

namespace MSAuth10PocApp;

/// <summary>
/// MSAuth 1.0 AT-POP (Access Token Proof-of-Possession) Demonstration Application
/// This application demonstrates end-to-end MSAuth 1.0 token acquisition and usage.
/// </summary>
class Program
{
    private static IConfiguration? _configuration;
    private static RSA? _popRsa;
    private static string? _popKeyId;
    private static string? _popJwk;

    static async Task<int> Main(string[] args)
    {
        try
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("MSAuth 1.0 AT-POP Demonstration Application");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            // Load configuration
            LoadConfiguration();

            // Validate configuration
            if (!ValidateConfiguration())
            {
                return 1;
            }

            // Step 1: Generate PoP key pair
            Console.WriteLine("[Step 1] Generating PoP key pair...");
            GeneratePopKeyPair();
            Console.WriteLine($"✓ Generated RSA key pair (KeyID: {_popKeyId})");
            Console.WriteLine();

            // Step 2: Acquire MSAuth 1.0 PoP token
            Console.WriteLine("[Step 2] Acquiring MSAuth 1.0 PoP token...");
            var authResult = await AcquireMsAuth10Token();
            Console.WriteLine("✓ Successfully acquired PoP token");
            Console.WriteLine($"  Token Type: {authResult.TokenType}");
            Console.WriteLine($"  Expires On: {authResult.ExpiresOn.ToLocalTime()}");
            Console.WriteLine($"  Scopes: {string.Join(", ", authResult.Scopes)}");
            Console.WriteLine();

            // Step 3: Inspect the access token
            Console.WriteLine("[Step 3] Inspecting PoP access token...");
            InspectToken(authResult.AccessToken);
            Console.WriteLine();

            // Step 4: Make API call with PoP token
            Console.WriteLine("[Step 4] Making API call with PoP token...");
            await CallApiWithPopToken(authResult.AccessToken);
            Console.WriteLine();

            Console.WriteLine("===========================================");
            Console.WriteLine("✓ MSAuth 1.0 demonstration completed successfully!");
            Console.WriteLine("===========================================");

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine();
            Console.WriteLine("===========================================");
            Console.WriteLine("❌ Error occurred:");
            Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
            Console.WriteLine("===========================================");
            Console.ResetColor();
            
            if (ex.InnerException != null)
            {
                Console.WriteLine();
                Console.WriteLine("Inner Exception:");
                Console.WriteLine($"{ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
            }

            return 1;
        }
        finally
        {
            // Dispose RSA instance to prevent resource leaks
            _popRsa?.Dispose();
        }
    }

    private static void LoadConfiguration()
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

        _configuration = builder.Build();
    }

    private static bool ValidateConfiguration()
    {
        if (_configuration == null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ Configuration not loaded");
            Console.ResetColor();
            return false;
        }

        var tenantId = _configuration["AzureAd:TenantId"];
        var clientId = _configuration["AzureAd:ClientId"];
        var certThumbprint = _configuration["AzureAd:CertificateThumbprint"];

        if (string.IsNullOrWhiteSpace(tenantId) || tenantId == "YOUR_TENANT_ID_HERE")
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ TenantId not configured in appsettings.json");
            Console.WriteLine("Please update the AzureAd:TenantId value.");
            Console.ResetColor();
            return false;
        }

        if (string.IsNullOrWhiteSpace(clientId) || clientId == "YOUR_CLIENT_ID_HERE")
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ ClientId not configured in appsettings.json");
            Console.WriteLine("Please update the AzureAd:ClientId value.");
            Console.ResetColor();
            return false;
        }

        if (string.IsNullOrWhiteSpace(certThumbprint) || certThumbprint == "YOUR_CERTIFICATE_THUMBPRINT_HERE")
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ CertificateThumbprint not configured in appsettings.json");
            Console.WriteLine("Please update the AzureAd:CertificateThumbprint value.");
            Console.ResetColor();
            return false;
        }

        Console.WriteLine("✓ Configuration validated");
        Console.WriteLine($"  Tenant ID: {tenantId}");
        Console.WriteLine($"  Client ID: {clientId}");
        Console.WriteLine($"  Certificate Thumbprint: {certThumbprint}");
        Console.WriteLine();

        return true;
    }

    private static void GeneratePopKeyPair()
    {
        // Generate a new RSA key pair for PoP
        _popRsa = RSA.Create(2048);
        _popKeyId = Guid.NewGuid().ToString();

        // Export public key as JWK
        var parameters = _popRsa.ExportParameters(false);
        var jwk = new
        {
            kty = "RSA",
            n = Base64UrlEncoder.Encode(parameters.Modulus!),
            e = Base64UrlEncoder.Encode(parameters.Exponent!),
            kid = _popKeyId,
            use = "sig"
        };

        _popJwk = JsonSerializer.Serialize(jwk);

        Console.WriteLine($"Public Key (JWK): {_popJwk}");
    }

    private static async Task<AuthenticationResult> AcquireMsAuth10Token()
    {
        var tenantId = _configuration!["AzureAd:TenantId"]!;
        var clientId = _configuration["AzureAd:ClientId"]!;
        var certThumbprint = _configuration["AzureAd:CertificateThumbprint"]!;
        var certStorePath = _configuration["AzureAd:CertificateStorePath"] ?? "CurrentUser/My";
        var scopes = _configuration.GetSection("TargetApi:Scopes").Get<string[]>() ?? new[] { "https://graph.microsoft.com/.default" };

        // Load certificate from store
        var certificateDescription = new CertificateDescription
        {
            SourceType = CertificateSource.StoreWithThumbprint,
            CertificateStorePath = certStorePath,
            CertificateThumbprint = certThumbprint
        };

        var loader = new DefaultCertificateLoader();
        loader.LoadIfNeeded(certificateDescription);

        if (certificateDescription.Certificate == null)
        {
            throw new InvalidOperationException($"Certificate not found with thumbprint: {certThumbprint}");
        }

        Console.WriteLine($"✓ Loaded certificate: {certificateDescription.Certificate.Subject}");

        // Build confidential client application with MSAL
        var app = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithCertificate(certificateDescription.Certificate)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithExperimentalFeatures()  // Required for WithAtPop extension
            .Build();

        // Acquire token with MSAuth 1.0 AT-POP
        var result = await app
            .AcquireTokenForClient(scopes)
            .WithAtPop(_popKeyId!, _popJwk!)
            .ExecuteAsync();

        return result;
    }

    private static void InspectToken(string accessToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(accessToken);

            Console.WriteLine("Access Token Claims:");
            Console.WriteLine($"  Issuer: {token.Issuer}");
            Console.WriteLine($"  Audiences: {string.Join(", ", token.Audiences)}");
            Console.WriteLine($"  Valid From: {token.ValidFrom.ToLocalTime()}");
            Console.WriteLine($"  Valid To: {token.ValidTo.ToLocalTime()}");

            // Look for cnf (confirmation) claim which binds the token to the public key
            var cnfClaim = token.Claims.FirstOrDefault(c => c.Type == "cnf");
            if (cnfClaim != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ Confirmation (cnf) claim found: {cnfClaim.Value}");
                Console.WriteLine("    This proves the token is bound to the PoP key!");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  ⚠ No confirmation (cnf) claim found");
                Console.WriteLine("    This might be a bearer token, not a PoP token");
                Console.ResetColor();
            }

            // Display all claims for inspection
            Console.WriteLine();
            Console.WriteLine("All Claims:");
            foreach (var claim in token.Claims)
            {
                var value = claim.Value.Length > 50 ? claim.Value.Substring(0, 47) + "..." : claim.Value;
                Console.WriteLine($"  {claim.Type}: {value}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not parse token as JWT: {ex.Message}");
        }
    }

    private static async Task CallApiWithPopToken(string accessToken)
    {
        var baseUrl = _configuration!["TargetApi:BaseUrl"] ?? "https://graph.microsoft.com/v1.0";
        var endpoint = _configuration["TargetApi:TestEndpoint"] ?? "/users?$top=1";
        var fullUrl = $"{baseUrl}{endpoint}";

        Console.WriteLine($"Calling API: {fullUrl}");

        // Note: For production applications, use HttpClientFactory or a shared HttpClient instance
        // to avoid socket exhaustion. This pattern is acceptable for demo purposes only.
        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var response = await httpClient.GetAsync(fullUrl);

        Console.WriteLine($"Response Status: {(int)response.StatusCode} {response.StatusCode}");

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ API call successful!");
            Console.ResetColor();
            
            // Pretty print the first 500 characters of the response
            var preview = content.Length > 500 ? content.Substring(0, 497) + "..." : content;
            Console.WriteLine();
            Console.WriteLine("Response Preview:");
            Console.WriteLine(preview);
        }
        else
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ API call failed");
            Console.WriteLine($"Error: {errorContent}");
            Console.ResetColor();
        }
    }
}
