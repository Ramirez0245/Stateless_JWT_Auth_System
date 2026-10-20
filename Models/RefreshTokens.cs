namespace AuthApi.Models;

/* Storing only the hash means a database leak doesn’t expose usable refresh tokens. 
ReplacedByTokenHash lets us detect reuse of a rotated token in Step 6. */
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    // We store a SHA-256 hash, never the raw token
    public string TokenHash { get; set; } = "";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    public string? CreatedByIp { get; set; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;
    public bool IsActive => RevokedAtUtc == null && !IsExpired;
}

/* Guid means Globally Unique Identifier: a 128-bit value used to identify something,
 such as a record or object, with a very low chance of duplicating another identifie 
 
 Guid.NewGuid() generates a new GUID using the .NET runtime and your operating 
 system’s supported mechanism. It’s not something you need to install or define yourself.*/