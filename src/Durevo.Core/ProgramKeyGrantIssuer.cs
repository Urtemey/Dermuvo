using System.Security.Cryptography;
using Durevo.Runtime;

namespace Durevo.Core;

public static class ProgramKeyGrantIssuer
{
    public static byte[] Issue(ECDsa issuer, byte[] license, byte[] programKey, ulong keyFeatures)
    {
        // Snapshot before checking: the signed binding must refer to the validated ticket.
        if (license is null || license.Length < 72 || license.Length > OfflineLicense.MaximumTicketBytes)
            throw new ArgumentException("Invalid license ticket size.");
        license = (byte[])license.Clone();
        var claims = OfflineLicense.VerifySignature(license, LicenseIssuer.ExportPublicKey(issuer));
        if ((claims.Features & keyFeatures) != keyFeatures)
            throw new UnauthorizedAccessException("License does not entitle this program-key feature group.");
        byte[] payload = ProgramKeyGrant.EncodeBinding(license, programKey, keyFeatures);
        byte[] signature = issuer.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return payload.Concat(signature).ToArray();
    }
}
