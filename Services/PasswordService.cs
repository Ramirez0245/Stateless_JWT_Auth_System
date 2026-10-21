using AuthApi.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services; // Places PasswordService in the AuthApi.Services namespace.

/* This defines a PasswordService class that hashes passwords and checks whether a password matches a stored hash. */

/* Declares a public class named PasswordService that implements the IPasswordService interface. 
It must provide the methods required by that interface. */
public class PasswordService : IPasswordService
{
    // OWASP guidance for PBKDF2-HMAC-SHA512 is 210,000+ iterations.
    /* field declaration with an initializer. It creates and 
    stores a PasswordHasher<User> object in _hasher. */
    /* PasswordHasher as the generic class and User as its type 
    argument. */
    /* Creates a PasswordHasher<User> and stores it in the private, read-only field _hasher. The 
    options set the iteration count to 210_000. The Options.Create(...) call wraps those settings 
    in the options object expected by the hasher. */
    private readonly PasswordHasher<User> _hasher = new(
        Microsoft.Extensions.Options.Options.Create(
            new PasswordHasherOptions { IterationCount = 210_000 }));

    // The user argument is unused by the default hasher.
    /* Defines Hash, which takes a password and returns its hashed form. null! supplies no 
    User object; ! suppresses the compiler’s nullable warning. The default hasher does not 
    need the user object for this operation. */
    public string Hash(string password) =>
        _hasher.HashPassword(null!, password);

    /* Defines Verify, which checks the provided password against the stored hash. It maps Identity’s result to the service’s PasswordVerifyResult:

        -> Success: the password matches.
        -> SuccessRehashNeeded: it matches, but the hash should be updated.
        -> _: any other result, including a mismatch, becomes Failed.
        The => syntax is an expression-bodied method: it returns the result of the expression to its right. */
    public PasswordVerifyResult Verify(string hash, string password) =>
        _hasher.VerifyHashedPassword(null!, hash, password) switch
        {
            PasswordVerificationResult.Success => PasswordVerifyResult.Success,
            PasswordVerificationResult.SuccessRehashNeeded => PasswordVerifyResult.SuccessRehashNeeded,
            _ => PasswordVerifyResult.Failed
        };
}