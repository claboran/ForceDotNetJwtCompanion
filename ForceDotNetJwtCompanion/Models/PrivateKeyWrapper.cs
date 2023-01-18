using Org.BouncyCastle.Math;

namespace ForceDotNetJwtCompanion.Models;

public class PrivateKeyWrapper
{
    public BigInteger Modulus { get; set; }

    public BigInteger Exponent { get; set; }
}