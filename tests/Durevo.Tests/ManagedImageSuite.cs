using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;
using Durevo.Fixture;

internal static class ManagedImageSuite
{
    internal static int Run(string temporaryRoot)
    {
        int count = 0;
        string root = Path.Combine(temporaryRoot, "managed-image");
        Directory.CreateDirectory(root);
        string dll = Path.Combine(root, "Durevo.Fixture.dll");
        byte[] original = File.ReadAllBytes(typeof(Cases).Assembly.Location);
        File.WriteAllBytes(dll, original);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ticket = ReleaseSigner.Create(root, "JuniorCoder", 7, signer);
        var release = SignedRelease.Verify(root, ticket, LicenseIssuer.ExportPublicKey(signer), "JuniorCoder", 7);
        void Check(bool value,string message) {count++;if(!value)throw new Exception(message);}
        void Reject(Action action,string message)
        {
            bool failed=false;
            try{action();}catch(Exception e) when(e is InvalidDataException or IOException or CryptographicException or ArgumentException or UnauthorizedAccessException){failed=true;}
            Check(failed,message);
        }
        var capture = VerifiedManagedImage.Capture(release, root, "Durevo.Fixture.dll");
        byte[] changed=(byte[])original.Clone(); changed[changed.Length/2]^=1;
        File.WriteAllBytes(dll,changed);
        Reject(()=>VerifiedManagedImage.Capture(release,root,"Durevo.Fixture.dll"),"Post-verification tamper accepted.");
        // Deleting the source proves Load cannot silently reopen that pathname.
        File.Delete(dll);
        var loaded=capture.Load();
        var type=loaded.GetType(typeof(Cases).FullName!)!;
        var method=type.GetMethod("Arithmetic")!;
        foreach(int value in new[]{int.MinValue,-17,0,17,int.MaxValue})
            Check(Equals(method.Invoke(null,[value,123]),Cases.Arithmetic(value,123)),"Captured assembly result differs.");
        Check(loaded.Location=="","Image was loaded from a disk pathname.");
        File.WriteAllBytes(dll,original);
        Reject(()=>VerifiedManagedImage.Capture(release,root,"unknown.dll"),"Unlisted image accepted.");
        Reject(()=>VerifiedManagedImage.Capture(release,root,"../escape.dll"),"Traversal accepted.");
        Reject(()=>VerifiedManagedImage.Capture(release,root,"Durevo.Fixture.dll",original.Length-1),"Size budget ignored.");
        var exposedHash=release.Files[0].Sha256; exposedHash[0]^=1;
        Check(VerifiedManagedImage.Capture(release,root,"Durevo.Fixture.dll").Revision==7,"Caller mutated verified inventory.");
        File.WriteAllBytes(dll,original[..^1]);
        Reject(()=>VerifiedManagedImage.Capture(release,root,"Durevo.Fixture.dll"),"Truncation accepted.");
        Console.WriteLine($"Managed image suite: {count} signed-byte/load checks passed.");
        return count;
    }
}
