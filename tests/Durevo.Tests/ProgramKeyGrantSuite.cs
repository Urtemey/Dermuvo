using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class ProgramKeyGrantSuite
{
    internal static int Run()
    {
        int checks = 0;
        void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
        void Reject(Action action, string message)
        {
            bool failed = false;
            try { action(); }
            catch (Exception e) when (e is CryptographicException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
            { failed = true; }
            Check(failed,message);
        }
        using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] publicKey = LicenseIssuer.ExportPublicKey(issuer);
        long now = 1500000;
        byte[] Ticket(string id = "license-A", ulong features = 3) => LicenseIssuer.Issue(issuer,
            new LicenseClaims(id,"JuniorCoder","test-device",1000000,2000000,features,2));
        byte[] license = Ticket();
        byte[] grant = ProgramKeyGrantIssuer.Issue(issuer,license,key,2);
        string keyId = EncryptedIntegerMachine.IdentifyKey(key);
        EncryptedIntegerMachine.KeyLease Activate(byte[] token, byte[]? ticket = null, byte[]? secret = null,
            string product = "JuniorCoder", string device = "test-device", string? expectedKey = null, uint seats = 1) =>
            ProgramKeyGrant.Activate(token,ticket ?? license,secret ?? key,publicKey,expectedKey ?? keyId,
                product,device,0,seats,() => DateTimeOffset.FromUnixTimeSeconds(now));
        try
        {
            Check(grant.Length == ProgramKeyGrant.GrantBytes && grant.AsSpan().IndexOf(key) < 0, "Grant contains key or wrong size.");
            for (int i = 0; i < grant.Length; i++)
            {
                byte[] changed = (byte[])grant.Clone(); changed[i] ^= 1;
                Reject(() => Activate(changed), "Mutated grant accepted.");
            }
            Reject(() => Activate(grant[..^1]), "Truncated grant accepted.");
            Reject(() => Activate(grant.Concat(new byte[]{0}).ToArray()), "Trailing grant bytes accepted.");
            Reject(() => Activate(grant, ticket:Ticket("license-B")), "Grant moved to another valid license.");
            Reject(() => Activate(grant, secret:RandomNumberGenerator.GetBytes(32)), "Wrong key accepted.");
            Reject(() => Activate(grant, product:"other"), "Wrong product accepted.");
            Reject(() => Activate(grant, device:"other"), "Wrong device accepted.");
            Reject(() => Activate(grant, seats:3), "Excess seat request accepted.");
            Reject(() => Activate(grant, expectedKey:Convert.ToBase64String(new byte[32])), "Wrong expected key ID accepted.");
            byte[] insufficient = Ticket(features:1);
            Reject(() => ProgramKeyGrantIssuer.Issue(issuer,insufficient,key,2), "Issuer granted an unentitled feature.");
            // Deliberately misissue with the signing primitive to test the independent client boundary.
            byte[] insufficientPayload = ProgramKeyGrant.EncodeBinding(insufficient,key,2);
            byte[] insufficientGrant = insufficientPayload.Concat(issuer.SignData(insufficientPayload,HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
            byte[] invalidPayload = OfflineLicense.EncodeClaims(new LicenseClaims("id", "JuniorCoder", "device", 1, 9, 3, 1));
            invalidPayload[0] ^= 1;
            byte[] wrongDomainTicket = invalidPayload.Concat(issuer.SignData(invalidPayload, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
            Reject(() => ProgramKeyGrantIssuer.Issue(issuer, wrongDomainTicket, key, 2), "Issuer accepted signed non-license payload.");
            Reject(() => Activate(insufficientGrant,ticket:insufficient), "Issuer-required feature ignored.");
            byte[] badDomain = ProgramKeyGrant.EncodeBinding(license,key,2);
            badDomain[0] ^= 1;
            byte[] badSigned = badDomain.Concat(issuer.SignData(badDomain,HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
            Reject(() => Activate(badSigned), "Signed wrong-domain grant accepted.");
            byte[] forged = (byte[])license.Clone(); forged[10] ^= 1;
            Reject(() => ProgramKeyGrantIssuer.Issue(issuer,forged,key,2), "Issuer accepted a forged license.");
            byte[] forgedBinding = ProgramKeyGrant.EncodeBinding(forged,key,2);
            byte[] authenticGrantForForged = forgedBinding.Concat(issuer.SignData(forgedBinding,HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
            Reject(() => Activate(authenticGrantForForged,ticket:forged), "Authentic grant bypassed license signature.");
            now = 2000000;
            Reject(() => Activate(grant), "Expired activation accepted.");
            now = 999999;
            Reject(() => Activate(grant), "Early activation accepted.");
            now = 1500000;
            using var encryption = new VmEncryptionKey(key);
            int xor = 18;
            int[] words = [(int)IntegerMachine.Operation.Constant,73,(int)IntegerMachine.Operation.Return,0];
            for(int i=0;i<words.Length;i++) words[i] ^= unchecked(xor+i*(int)0x9e3779b9);
            string envelope = encryption.Seal(words,0,1,0,xor,false,"grant-suite");
            int Run() => EncryptedIntegerMachine.Run(envelope,keyId,"grant-suite",[]);
            using (var lease = Activate(grant))
            {
                // Caller buffer mutation after verification must not change installed authorization/key.
                byte[] saved = (byte[])grant.Clone(); grant[0] ^= 1;
                Check(Run()==73,"Valid grant did not enable encrypted VM.");
                grant = saved;
                now = 1999999; Check(Run()==73,"Last valid second denied.");
                now = 2000000; Reject(() => Run(),"Lease remained usable after expiration.");
                now = 1500000; Reject(() => Run(),"Expired lease resurrected after clock rollback.");
            }
            Reject(() => Run(),"Disposed granted key remained available.");
            EncryptedIntegerMachine.KeyLease? reentrant = null;
            reentrant = ProgramKeyGrant.Activate(grant,license,key,publicKey,keyId,"JuniorCoder","test-device",0,1,
                () => { reentrant?.Dispose(); return DateTimeOffset.FromUnixTimeSeconds(now); });
            using (reentrant) Reject(() => Run(),"Clock callback disposal raced key snapshot.");
            Console.WriteLine($"Program-key grants: {checks} binding/entitlement/expiry checks passed.");
            return checks;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
