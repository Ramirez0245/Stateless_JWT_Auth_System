using System.Security.Cryptography;
using System.Text;
using AuthApi.Models;
using AuthApi.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

/* TokenService is responsible for creating signed access tokens and generating refresh tokens. 
In a Clean Architecture setup, the service lives in the Services directory as an implementation
of ITokenService; other parts of the app can depend on the interface without needing to know
how tokens are created. */
public class TokenService : ITokenService
{
    // JwtOptions holds configuration such as the signing key, issuer, audience, and access-token lifetime.
    private readonly JwtOptions _opts;

    // JsonWebTokenHandler creates the JWT. 
    private readonly JsonWebTokenHandler _handler = new();

    // SigningCredentials tells it to sign using HMAC-SHA256.
    private readonly SigningCredentials _creds;

    // IOptions<JwtOptions> lets the service receive those settings through dependency injection.
    /* This is a C# constructor for a TokenService. It reads JWT settings 
    and prepares the credentials used to sign tokens: 
    IOptions<JwtOptions> options supplies configuration values for JwtOptions.

    

    
    - _creds = ... stores the credentials, typically so another method can use them when creating JWTs.*/
    /* IOptions<JwtOptions> options is a dependency-injected wrapper that gives TokenService access to 
    configuration values bound to the JwtOptions class.
    - IOptions<T> is part of .NET’s options pattern.
    - JwtOptions is the class describing your JWT settings—likely including Key.
    - options.Value returns the configured JwtOptions object, which your code stores in _opts. */
    public TokenService(IOptions<JwtOptions> options)
    {
        // - _opts = options.Value; saves those settings in the service.
        _opts = options.Value;
        // - Convert.FromBase64String(_opts.Key) decodes the configured key from Base64 into bytes. The setting must contain valid Base64.
        var keyBytes = Convert.FromBase64String(_opts.Key);
        //     - new SymmetricSecurityKey(keyBytes) creates a signing key from those bytes. “Symmetric” means the same secret key signs and verifies the token.
        _creds = new SigningCredentials(
            // - SigningCredentials(..., SecurityAlgorithms.HmacSha256) pairs that key with the HMAC-SHA256 signing algorithm.
            new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
    }


    /* 
    3. Adds these claims:
        sub: the user’s ID, the standard subject identifier.
        email: the user’s email.
        jti: a unique ID for this particular token.
        role: the user’s role, often used for authorization. */
    public AccessToken CreateAccessToken(User user)
    {
        // 1. Calculates an expiration time using the configured lifetime. 
        var expires = DateTime.UtcNow.AddMinutes(_opts.AccessTokenMinutes);

        //  2. Builds a token descriptor containing the issuer, audience, issue time, 
        //  “valid from” time, expiry, signing credentials, and claims.
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _opts.Issuer,
            Audience = _opts.Audience,
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            Expires = expires,
            SigningCredentials = _creds,
            /*  3. Adds these claims:
                    sub: the user’s ID, the standard subject identifier.
                    email: the user’s email.
                    jti: a unique ID for this particular token.
                role: the user’s role, often used for authorization. */
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = user.Id.ToString(),
                [JwtRegisteredClaimNames.Email] = user.Email,
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString(),
                ["role"] = user.Role
            }
        };

        // 4. Creates the signed JWT and returns it with its expiration time in an AccessToken object.
        return new AccessToken(_handler.CreateToken(descriptor), expires);
    }

    // GenerateRefreshToken() creates 64 cryptographically random bytes, then encodes them as a URL-safe string
    /* Hashing a refresh token before storing it means a database leak does not directly 
    expose usable refresh tokens. HashToken uses SHA-256; that is appropriate here because
     the original token is randomly generated with high entropy, unlike a human-chosen
      password. When a client presents a refresh token, the server should hash it and 
      compare the result with the stored hash. Refresh tokens should also have expiry 
      and revocation tracking, and ideally be rotated when used. */
    public RefreshTokenPair GenerateRefreshToken()
    {
        //Generate secure random bytes and Encode them as a URL-safe string
        var raw = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(64));
        // Converts the bytes into a string that can be safely sent in URLs or HTTP 
        // headers. This is the raw refresh token.
        return new RefreshTokenPair(raw, HashToken(raw));
    }

    // SHA-256 is fine here: the input is 512 bits of randomness, not a password.
    public string HashToken(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
}