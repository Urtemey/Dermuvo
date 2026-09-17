using System.Security.Cryptography;
using Durevo.Runtime;
namespace Durevo.Core;

public static class ReleaseSigner
{
    public static byte[] Create(string root, string product, ulong revision, ECDsa issuer)
    {
        if (issuer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new ArgumentException("Expected P-256 signer.");
        var inventory = ReleaseInventory.Capture(root);
        byte[] payload = SignedRelease.Encode(product, revision, inventory);
        byte[] signature = issuer.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return payload.Concat(signature).ToArray();
    }
}
