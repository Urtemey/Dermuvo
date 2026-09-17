using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Durevo.Runtime;

// Verification only. Private keys and signing remain in the build-time tool.
// Explicit fixed-width P1363 avoids provider-specific DER signature conventions.
internal static class P256Signature
{
    internal static bool Verify(byte[] payload, byte[] signature, byte[] publicKey)
    {
        if (signature.Length != 64 || publicKey.Length != 65 || publicKey[0] != 4) return false;
        try
        {
            var curve = SecNamedCurves.GetByName("secp256r1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var point = curve.Curve.DecodePoint(publicKey);
            var key = new ECPublicKeyParameters(point, domain);
            byte[] rBytes = new byte[32], sBytes = new byte[32];
            Array.Copy(signature, 0, rBytes, 0, 32);
            Array.Copy(signature, 32, sBytes, 0, 32);
            var r = new BigInteger(1, rBytes);
            var s = new BigInteger(1, sBytes);
            if (r.SignValue <= 0 || s.SignValue <= 0 || r.CompareTo(curve.N) >= 0 || s.CompareTo(curve.N) >= 0)
                return false;
            using var sha = SHA256.Create();
            var verifier = new ECDsaSigner();
            verifier.Init(false, key);
            return verifier.VerifySignature(sha.ComputeHash(payload), r, s);
        }
        catch (ArgumentException) { return false; } // Invalid/non-curve public point.
    }
}
