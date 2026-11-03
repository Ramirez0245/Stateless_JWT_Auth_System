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

    private const string InvalidTokenMessage = "Invalid or expired refresh token.";
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

        var (response, refreshEntity) = BuildTokens(user, ipAddress);
        _db.RefreshTokens.Add(refreshEntity);
        await _db.SaveChangesAsync(ct);

        return new(response);
    }

    // Builds an access token + a new (unsaved) refresh token entity
    private (AuthResponse Response, RefreshToken Entity) BuildTokens(User user, string? ip)
    {
        var access = _tokens.CreateAccessToken(user);
        var refresh = _tokens.GenerateRefreshToken();
        var refreshExpires = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays);

        var entity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refresh.Hash,
            ExpiresAtUtc = refreshExpires,
            CreatedByIp = ip
        };

        var response = new AuthResponse
        {
            AccessToken = access.Token,
            AccessTokenExpiresAtUtc = access.ExpiresAtUtc,
            RefreshToken = refresh.Raw,
            RefreshTokenExpiresAtUtc = refreshExpires
        };

        return (response, entity);
    }

    public async Task<AuthResult<AuthResponse>> RefreshAsync(
        string rawRefreshToken, string? ipAddress, CancellationToken ct)
    {
        var invalid = new AuthResult<AuthResponse>(null, AuthFailure.InvalidToken, InvalidTokenMessage);

        var hash = _tokens.HashToken(rawRefreshToken);
        var existing = await _db.RefreshTokens
            .Include(t => t.User)
            .SingleOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (existing is null)
            return invalid;

        if (existing.RevokedAtUtc is not null)
        {
            // A token that was already rotated is being replayed: assume compromise
            if (existing.ReplacedByTokenHash is not null)
                await RevokeAllForUserAsync(existing.UserId, ct);

            return invalid;
        }

        if (existing.IsExpired)
            return invalid;

        var (response, newToken) = BuildTokens(existing.User, ipAddress);
        var now = DateTime.UtcNow;

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        // Atomic "claim": only one concurrent request can revoke this token
        var claimed = await _db.RefreshTokens
            .Where(t => t.Id == existing.Id && t.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAtUtc, now)
                .SetProperty(t => t.ReplacedByTokenHash, newToken.TokenHash), ct);

        if (claimed == 0)
            return invalid; // lost a race with another refresh using the same token

        _db.RefreshTokens.Add(newToken);
        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        return new(response);
    }

    public async Task LogoutAsync(string rawRefreshToken, CancellationToken ct)
    {
        var hash = _tokens.HashToken(rawRefreshToken);
        var now = DateTime.UtcNow;

        await _db.RefreshTokens
            .Where(t => t.TokenHash == hash && t.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAtUtc, now), ct);
    }

    public Task LogoutAllAsync(Guid userId, CancellationToken ct) =>
        RevokeAllForUserAsync(userId, ct);

    private async Task RevokeAllForUserAsync(Guid userId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        await _db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAtUtc, now), ct);
    }
    private static string NormalizeEmail(string email) =>
        email.Trim().ToLowerInvariant();
}