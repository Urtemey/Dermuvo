using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class LicenseSuite
{
    internal static int Run()
    {
        int checks = 0;
        using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = LicenseIssuer.ExportPublicKey(issuer);
        var claims = new LicenseClaims("test-license-only", "JuniorCoder", "synthetic-school-device",
            1000000, 2000000, 0b1011, 13);
        var ticket = LicenseIssuer.Issue(issuer, claims);
        LicenseClaims Verify(byte[] bytes, byte[]? key = null, string product = "JuniorCoder",
            string device = "synthetic-school-device", ulong features = 3, uint seats = 13, long time = 1500000) =>
            OfflineLicense.Verify(bytes, key ?? publicKey, product, device, features, seats,
                DateTimeOffset.FromUnixTimeSeconds(time));
        void Assert(bool value, string message)
        {
            checks++; if (!value) throw new Exception(message);
        }
        void Reject(Action action, string message)
        {
            bool rejected = false;
            try { action(); }
            catch (Exception e) when (e is CryptographicException or InvalidDataException or
                UnauthorizedAccessException or ArgumentException or EndOfStreamException) { rejected = true; }
            Assert(rejected, message);
        }
        byte[] SignedRaw(byte[] payload) => payload.Concat(issuer.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();

        Assert(Verify(ticket).Id == claims.Id, "Valid license rejected.");
        Assert(Verify(ticket, time: 1000000).Seats == 13, "NotBefore boundary rejected.");
        Assert(Verify(ticket, time: 1999999).Features == 11, "Last valid second rejected.");
        Reject(() => Verify(ticket, time: 999999), "Early license accepted.");
        Reject(() => Verify(ticket, time: 2000000), "Expiration boundary accepted.");
        Reject(() => Verify(ticket, key: LicenseIssuer.ExportPublicKey(other)), "Wrong trust anchor accepted.");
        Reject(() => Verify(ticket, product: "juniorcoder"), "Wrong product accepted.");
        Reject(() => Verify(ticket, device: "other-device"), "Wrong device accepted.");
        Reject(() => Verify(ticket, features: 4), "Unlicensed feature accepted.");
        Reject(() => Verify(ticket, seats: 14), "Seat limit exceeded.");
        Reject(() => Verify(ticket, seats: 0), "Empty seat request accepted.");
        Reject(() => Verify(ticket, product: ""), "Empty product accepted.");
        for (int index = 0; index < ticket.Length; index++)
            for (int bit = 0; bit < 8; bit++)
            {
                var modified = (byte[])ticket.Clone(); modified[index] ^= (byte)(1 << bit);
                Reject(() => Verify(modified), "Modified ticket accepted.");
            }
        for (int size = 0; size < ticket.Length; size++)
        {
            var truncated = ticket.Take(size).ToArray();
            Reject(() => Verify(truncated), "Truncated ticket accepted.");
        }
        Reject(() => Verify(new byte[OfflineLicense.MaximumTicketBytes + 1]), "Oversized ticket accepted.");
        Reject(() => Verify(ticket.Concat(new byte[] { 0 }).ToArray()), "Appended ticket accepted.");
        var invalidPoint = new byte[65]; invalidPoint[0] = 4;
        Reject(() => Verify(ticket, key: invalidPoint), "Off-curve public key accepted.");
        var invalidScalar = (byte[])ticket.Clone();
        Array.Clear(invalidScalar, invalidScalar.Length - 64, 32);
        Reject(() => Verify(invalidScalar), "Zero ECDSA r accepted.");
        invalidScalar = (byte[])ticket.Clone();
        Array.Fill(invalidScalar, (byte)255, invalidScalar.Length - 32, 32);
        Reject(() => Verify(invalidScalar), "Out-of-range ECDSA s accepted.");
        var payload = OfflineLicense.EncodeClaims(claims);
        payload[0] ^= 1;
        Reject(() => Verify(SignedRaw(payload)), "Wrong signed domain accepted.");
        payload = OfflineLicense.EncodeClaims(claims);
        payload[8] = 255; payload[9] = 255;
        Reject(() => Verify(SignedRaw(payload)), "Oversized signed identifier accepted.");
        payload = OfflineLicense.EncodeClaims(claims);
        Reject(() => Verify(SignedRaw(payload.Concat(new byte[] { 0 }).ToArray())), "Signed trailing data accepted.");
        Reject(() => new LicenseClaims("x", "y", "z", 0, 0, 1, 1), "Empty interval accepted.");
        Reject(() => new LicenseClaims("x", "y", "z", 0, 1, 1, 0), "Zero licensed seats accepted.");
        Reject(() => new LicenseClaims("x", "y", new string('я', 129), 0, 1, 1, 1), "Oversized UTF8 identifier accepted.");
        Reject(() => new LicenseClaims("x", "y", "\ud800", 0, 1, 1, 1), "Invalid UTF16 identifier accepted.");
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Reject(() => LicenseIssuer.Issue(wrongCurve, claims), "Wrong signing curve accepted.");
        // Public-only authority must not be sufficient to issue.
        using var publicOnly = ECDsa.Create(issuer.ExportParameters(false));
        Reject(() => LicenseIssuer.Issue(publicOnly, claims), "Public key issued a license.");
        Console.WriteLine($"License suite: {checks} checks passed (ephemeral test keys only).");
        return checks;
    }
}
