namespace AuthApi.Services;

public enum PasswordVerifyResult { Failed, Success, SuccessRehashNeeded }

public interface IPasswordService
{
    string Hash(string password);
    PasswordVerifyResult Verify(string hash, string password);
}