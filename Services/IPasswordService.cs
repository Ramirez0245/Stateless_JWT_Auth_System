namespace AuthApi.Services;

public enum PasswordVerifyResult { Failed, Success, SuccessRehashNeeded }

public interface IPasswordService
{
    string Hash(string password);
    PasswordVerifyResult Verify(string hash, string password);

    /* When the email doesn’t exist, we still run a hash verification 
    so response time doesn’t reveal which emails are registered. 
    That needs a precomputed dummy hash, created once at startup. */
    string DummyHash { get; }   // ★ new
}