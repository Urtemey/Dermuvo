using System.Diagnostics;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class ReleaseCliSuite
{
    internal static int Run(string temporaryRoot, string cli)
    {
        cli = Path.GetFullPath(cli);
        if (!File.Exists(cli)) throw new FileNotFoundException("Build CLI before integration tests.", cli);
        string root = Path.Combine(temporaryRoot, "cli-release");
        Directory.CreateDirectory(root);
        string dll = Path.Combine(root,"sample.dll"); File.WriteAllBytes(dll,[1,2,3]);
        string privatePath=Path.Combine(temporaryRoot,"ephemeral-encrypted-key.pem");
        string publicPath=Path.Combine(temporaryRoot,"ephemeral-public-key.bin");
        string password=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var signer=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(privatePath,signer.ExportEncryptedPkcs8PrivateKeyPem(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc,HashAlgorithmName.SHA256,100000)));
        File.WriteAllBytes(publicPath,LicenseIssuer.ExportPublicKey(signer));
        string programKeyPath = Path.Combine(temporaryRoot, "synthetic-program.vmkey");
        int checks=0;
        (int Code,string Text) RunCommand(string pass,params string[] arguments)
        {
            var info=new ProcessStartInfo("dotnet") {UseShellExecute=false,CreateNoWindow=true,
                RedirectStandardOutput=true,RedirectStandardError=true};
            info.ArgumentList.Add(cli); foreach(var argument in arguments) info.ArgumentList.Add(argument);
            info.Environment["DUREVO_KEY_PASSWORD"]=pass;
            using var process=Process.Start(info)!;
            var stdout=process.StandardOutput.ReadToEndAsync();
            var stderr=process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000)) { process.Kill(entireProcessTree:true); throw new TimeoutException("CLI test timeout."); }
            string text=stdout.GetAwaiter().GetResult()+stderr.GetAwaiter().GetResult();
            if(text.Contains(pass,StringComparison.Ordinal)) throw new Exception("CLI echoed a password.");
            return(process.ExitCode,text);
        }
        void Check(bool condition,string message) {checks++;if(!condition)throw new Exception(message);}
        try
        {
            var analyzed = RunCommand(password, "analyze", typeof(Durevo.Fixture.Cases).Assembly.Location);
            Check(analyzed.Code == 0, "CLI analysis failed: " + analyzed.Text);
            using (var json = System.Text.Json.JsonDocument.Parse(analyzed.Text))
                Check(json.RootElement.GetProperty("IntegerVmEligible").GetInt32() > 0 &&
                    json.RootElement.GetProperty("Sha256").GetString() == Convert.ToHexString(
                        SHA256.HashData(File.ReadAllBytes(typeof(Durevo.Fixture.Cases).Assembly.Location))),
                    "CLI analysis report identity/eligibility mismatch.");
            Check(RunCommand(password, "analyze", dll).Code != 0, "Malformed assembly accepted by analysis.");
            var bad=RunCommand("wrong-password-for-test", "sign-release",root,"JuniorCoder","5",privatePath);
            Check(bad.Code!=0 && !File.Exists(Path.Combine(root,ReleaseInventory.ManifestName)),"Wrong password published a manifest.");
            var signed=RunCommand(password,"sign-release",root,"JuniorCoder","5",privatePath);
            Check(signed.Code==0,"CLI signing failed: "+signed.Text);
            var verified=RunCommand(password,"verify-release",root,publicPath,"JuniorCoder","5");
            Check(verified.Code==0,"CLI verification failed: "+verified.Text);
            Check(RunCommand(password,"verify-release",root,publicPath,"JuniorCoder","6").Code!=0,"CLI accepted rollback.");
            byte[] original=File.ReadAllBytes(Path.Combine(root,ReleaseInventory.ManifestName));
            Check(RunCommand(password,"sign-release",root,"JuniorCoder","6",privatePath).Code!=0,"CLI overwrote manifest.");
            Check(original.SequenceEqual(File.ReadAllBytes(Path.Combine(root,ReleaseInventory.ManifestName))),"Failed signing changed manifest.");
            File.WriteAllBytes(dll,[1,2,4]);
            Check(RunCommand(password,"verify-release",root,publicPath,"JuniorCoder","5").Code!=0,"CLI accepted modified assembly.");
            File.WriteAllBytes(dll,[1,2,3]);
            string inside=Path.Combine(root,"issuer.pem"); File.Copy(privatePath,inside);
            var forbidden=RunCommand(password,"sign-release",root,"JuniorCoder","7",inside);
            Check(forbidden.Code!=0 && forbidden.Text.Contains("outside"),"Signing key allowed inside release.");
            File.Delete(inside);
            File.WriteAllBytes(Path.Combine(root,ReleaseInventory.ManifestName),new byte[SignedRelease.MaximumManifestBytes+1]);
            Check(RunCommand(password,"verify-release",root,publicPath,"JuniorCoder","5").Code!=0,"CLI accepted oversized manifest.");
            File.WriteAllBytes(Path.Combine(root,ReleaseInventory.ManifestName),original);
            string vmOutput = Path.Combine(temporaryRoot, "cli-vm");
            string methods = Path.Combine(temporaryRoot, "methods.txt");
            File.WriteAllText(methods, "System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)");
            var published = RunCommand(password, "virtualize", typeof(Durevo.Fixture.Cases).Assembly.Location, vmOutput, methods);
            Check(published.Code == 0, "CLI VM publication failed: " + published.Text);
            Check(File.Exists(Path.Combine(vmOutput, "Mono.Cecil.dll")) && File.Exists(Path.Combine(vmOutput, "Mono.Cecil.LICENSE.txt")),
                "Graph inspection dependency or license omitted.");
            string crypto = Path.Combine(vmOutput, "BouncyCastle.Cryptography.dll");
            Check(File.Exists(crypto) && File.Exists(Path.Combine(vmOutput, "BouncyCastle.LICENSE.md")),
                "Runtime dependency or license omitted.");
            using (var module = Mono.Cecil.ModuleDefinition.ReadModule(crypto))
                Check(module.Assembly.CustomAttributes.Any(a => a.AttributeType.FullName == "System.Runtime.Versioning.TargetFrameworkAttribute"
                    && (string)a.ConstructorArguments[0].Value == ".NETStandard,Version=v2.0"),
                    "CLI shipped a desktop-only cryptography assembly.");
            Check(RunCommand(password, "new-program-key", programKeyPath).Code == 0, "Program key creation failed.");
            byte[] programKey = File.ReadAllBytes(programKeyPath);
            try
            {
                Check(programKey.Length == 32, "Wrong program key size.");
                Check(RunCommand(password, "new-program-key", programKeyPath).Code != 0, "Program key overwritten.");
                Check(programKey.SequenceEqual(File.ReadAllBytes(programKeyPath)), "Refused overwrite changed key.");
                string encryptedOutput = Path.Combine(temporaryRoot, "cli-encrypted-vm");
                var encrypted = RunCommand(password,"virtualize-encrypted",typeof(Durevo.Fixture.Cases).Assembly.Location,
                    encryptedOutput,methods,programKeyPath);
                Check(encrypted.Code == 0, "Encrypted CLI compilation failed: " + encrypted.Text);
                Check(!encrypted.Text.Contains(Convert.ToBase64String(programKey),StringComparison.Ordinal), "CLI printed the key.");
                Check(!File.Exists(Path.Combine(encryptedOutput,Path.GetFileName(programKeyPath))), "CLI distributed the private program key.");
                checks += ProtectedReleaseCliSuite.Run(temporaryRoot, cli, privatePath, password, publicPath, programKeyPath, programKey);
                string ticketPath = Path.Combine(temporaryRoot,"key-license.bin");
                string grantPath = Path.Combine(temporaryRoot,"key-grant.bin");
                byte[] license = LicenseIssuer.Issue(signer,new LicenseClaims("cli-license","JuniorCoder","cli-device",
                    1000000,2000000,2,1));
                File.WriteAllBytes(ticketPath,license);
                var issued = RunCommand(password,"issue-program-grant",ticketPath,programKeyPath,"2",privatePath,grantPath);
                Check(issued.Code == 0,"Grant CLI failed: " + issued.Text);
                byte[] grant = File.ReadAllBytes(grantPath);
                using (var lease = ProgramKeyGrant.Activate(grant,license,programKey,LicenseIssuer.ExportPublicKey(signer),
                    EncryptedIntegerMachine.IdentifyKey(programKey),"JuniorCoder","cli-device",0,1,
                    () => DateTimeOffset.FromUnixTimeSeconds(1500000)))
                    Check(lease.KeyId == EncryptedIntegerMachine.IdentifyKey(programKey),"CLI grant activation failed.");
                Check(RunCommand(password,"issue-program-grant",ticketPath,programKeyPath,"2",privatePath,grantPath).Code != 0,
                    "CLI overwrote grant.");
                Check(grant.SequenceEqual(File.ReadAllBytes(grantPath)),"Failed grant write changed existing file.");
                license[10] ^= 1; File.WriteAllBytes(ticketPath,license);
                string rejectedGrant = Path.Combine(temporaryRoot,"rejected-grant.bin");
                Check(RunCommand(password,"issue-program-grant",ticketPath,programKeyPath,"2",privatePath,rejectedGrant).Code != 0
                    && !File.Exists(rejectedGrant),"CLI issued grant for forged license.");
                foreach (string file in Directory.GetFiles(encryptedOutput))
                    Check(File.ReadAllBytes(file).AsSpan().IndexOf(programKey) < 0, "Program key leaked into published artifact.");
            }
            finally { CryptographicOperations.ZeroMemory(programKey); }
            Console.WriteLine($"Release CLI suite: {checks} subprocess checks passed.");
            return checks;
        }
        finally { File.Delete(privatePath); if (File.Exists(programKeyPath)) File.Delete(programKeyPath); }
    }
}
