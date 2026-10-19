namespace AuthApi.Options;

public class JwtOptions
{
    public const string Section = "Jwt";

    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";
    public string Key { get; set; } = "";
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 7;
}
/* Short-lived access tokens (15 min) plus rotating refresh tokens is 
 the industry standard pattern we’ll build toward. */