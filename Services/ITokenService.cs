using AuthApi.Models;

namespace AuthApi.Services;

public record AccessToken(string Token, DateTime ExpiresAtUtc);
public record RefreshTokenPair(string Raw, string Hash);

public interface ITokenService
{
    AccessToken CreateAccessToken(User user);
    RefreshTokenPair GenerateRefreshToken();
    string HashToken(string rawToken);
}