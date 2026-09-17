using System.Security.Cryptography;
using Durevo.Runtime;

namespace Durevo.Core;

// Build/issuer-side only. No private key or issuing method is shipped in Durevo.Runtime.
public static class LicenseIssuer
{
    public static byte[] Issue(ECDsa privateKey, LicenseClaims claims)
    {
        if (privateKey.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new ArgumentException("License issuance requires P-256.");
        byte[] payload = OfflineLicense.EncodeClaims(claims);
        byte[] signature = privateKey.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64) throw new CryptographicException("Unexpected signature length.");
        return payload.Concat(signature).ToArray();
    }

    public static byte[] ExportPublicKey(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        if (parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
            parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
            throw new ArgumentException("Expected P-256.");
        return new byte[] { 4 }.Concat(parameters.Q.X).Concat(parameters.Q.Y).ToArray();
    }
}
