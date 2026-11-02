using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using AuthApi.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MySqlConnector;

namespace AuthApi.Services;

public class AuthService : IAuthService
{
    private const string InvalidCredsMessage = "Invalid email or password.";

    private readonly AppDbContext _db;
    private readonly IPasswordService _passwords;
    private readonly ITokenService _tokens;
    private readonly JwtOptions _jwt;

    public AuthService(
        AppDbContext db,
        IPasswordService passwords,
        ITokenService tokens,
        IOptions<JwtOptions> jwt)
    {
        _db = db;
        _passwords = passwords;
        _tokens = tokens;
        _jwt = jwt.Value;
    }

    // 
    public async Task<AuthResult<RegisteredUser>> RegisterAsync(
        RegisterRequest request, CancellationToken ct)
    {
        var passwordError = PasswordPolicy.Validate(request.Password);
        if (passwordError is not null)
            return new(null, AuthFailure.InvalidInput, passwordError);

        var email = NormalizeEmail(request.Email);

        if (await _db.Users.AnyAsync(u => u.Email == email, ct))
            return new(null, AuthFailure.EmailTaken, "Email is already registered.");

        var user = new User
        {
            Email = email,
            PasswordHash = _passwords.Hash(request.Password),
            Role = "User" // never taken from the request
        };

        _db.Users.Add(user);

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex)
            when (ex.InnerException is MySqlException { ErrorCode: MySqlErrorCode.DuplicateKeyEntry })
        {
            // Lost a race with a concurrent registration of the same email
            return new(null, AuthFailure.EmailTaken, "Email is already registered.");
        }

        return new(new RegisteredUser(user.Id, user.Email));
    }

    public async Task<AuthResult<AuthResponse>> LoginAsync(
        LoginRequest request, string? ipAddress, CancellationToken ct)
    {
        // Cap input length so nobody can force expensive hashing of huge strings
        if (request.Password.Length > PasswordPolicy.MaxLength)
            return new(null, AuthFailure.InvalidCredentials, InvalidCredsMessage);

        var email = NormalizeEmail(request.Email);
        var user = await _db.Users.SingleOrDefaultAsync(u => u.Email == email, ct);

        if (user is null)
        {
            // Burn the same CPU time as a real check to blunt timing-based user enumeration
            _passwords.Verify(_passwords.DummyHash, request.Password);
            return new(null, AuthFailure.InvalidCredentials, InvalidCredsMessage);
        }

        var verify = _passwords.Verify(user.PasswordHash, request.Password);
        if (verify == PasswordVerifyResult.Failed)
            return new(null, AuthFailure.InvalidCredentials, InvalidCredsMessage);

        if (verify == PasswordVerifyResult.SuccessRehashNeeded)
            user.PasswordHash = _passwords.Hash(request.Password);

        var access = _tokens.CreateAccessToken(user);
        var refresh = _tokens.GenerateRefreshToken();
        var refreshExpires = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays);

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refresh.Hash,
            ExpiresAtUtc = refreshExpires,
            CreatedByIp = ipAddress
        });

        await _db.SaveChangesAsync(ct);

        return new(new AuthResponse
        {
            AccessToken = access.Token,
            AccessTokenExpiresAtUtc = access.ExpiresAtUtc,
            RefreshToken = refresh.Raw,
            RefreshTokenExpiresAtUtc = refreshExpires
        });
    }

    private static string NormalizeEmail(string email) =>
        email.Trim().ToLowerInvariant();
}