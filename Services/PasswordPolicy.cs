namespace AuthApi.Services;

public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128; // caps hashing cost per request

    public static string? Validate(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return "Password is required.";
        if (password.Length < MinLength)
            return $"Password must be at least {MinLength} characters.";
        if (password.Length > MaxLength)
            return $"Password must be at most {MaxLength} characters.";
        return null;
    }
}