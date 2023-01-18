using Org.BouncyCastle.OpenSsl;

namespace ForceDotNetJwtCompanion.Models;

/// <summary>
/// PasswordFinder
/// BouncyCastle's PasswordFinder
///
/// <see>https://stackoverflow.com/questions/44767290/decrypt-passphrase-protected-pem-containing-private-key</see>
/// 
/// </summary>
public class PasswordFinder : IPasswordFinder
{
    private readonly string _password;

    public PasswordFinder(string password)
    {
        _password = password;
    }
        
    public char[] GetPassword() => _password.ToCharArray();
}