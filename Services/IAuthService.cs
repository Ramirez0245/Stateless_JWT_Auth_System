using AuthApi.DTOs;

namespace AuthApi.Services;

public enum AuthFailure { None, InvalidInput, EmailTaken, InvalidCredentials, InvalidToken }

public record AuthResult<T>(T? Value, AuthFailure Failure = AuthFailure.None, string? Message = null)
{
    public bool Succeeded => Failure == AuthFailure.None;
}

public record RegisteredUser(Guid Id, string Email);

public interface IAuthService
{
    // <AuthResult<RegisteredUser>>  - Nested Generic Type Syntax
    // AuthResult is a generic type parameterized with RegisteredUser
    // the outer Task is parameterized with that result type.
    Task<AuthResult<RegisteredUser>> RegisterAsync(RegisterRequest request, CancellationToken ct);
    Task<AuthResult<AuthResponse>> LoginAsync(LoginRequest request, string? ipAddress, CancellationToken ct);
    Task<AuthResult<AuthResponse>> RefreshAsync(string rawRefreshToken, string? ipAddress, CancellationToken ct);
    Task LogoutAsync(string rawRefreshToken, CancellationToken ct);
    Task LogoutAllAsync(Guid userId, CancellationToken ct);
}