using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace test
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            //openssl genrsa -out private.pem 2048
            //openssl req -sha256 -new -key private.pem -out csr.pem

            //openssl rsa -in private.pem -text -noout
            //openssl req -in csr.pem -text -noout

            //openssl sha256 tbs.cer

            //test.exe ksg.cer csr.pem
            // get its signature - enter

            // test.exe SignCert tbs.cer tbs.sig

            //openssl x509 -in cert.cer -inform der -text

            //openssl verify -verbose -CAfile <(cat Intermediate.pem RootCert.pem) UserCert.pem
            //openssl pkcs7 -print_certs -in ksg.p7b -inform DER -out certificate.cer -outform pem

            //openssl x509 -inform DER -in cert.cer -outform PEM -out cert.pem


            Console.WriteLine("Usage: test2.exe 'issuer.cer' 'dronecsr.csr' ");
            Console.WriteLine("Usage: test2.exe SignCert 'tbs.cer' 'tbs.sig' ");
            if (args.Length == 2)
            {
                cert.CreateCert(args[0], args[1]);
            }
            else if (args.Length == 3 && args[0] == "SignCert")
            {
                cert.SignCert(args[1],args[2]);
            }
            else
            {
                Console.WriteLine("No Command");
            }
        }
    }

    public class cert
    {
        public static void CreateCert(string parentcer, string csrFile)
        {
            var issuer = new X509CertificateParser().ReadCertificate(File.OpenRead(parentcer));

            var reader = new PemReader(File.OpenText(csrFile));

            var csr = (Pkcs10CertificationRequest)(reader.ReadObject());
            var csrinfo = csr.GetCertificationRequestInfo();

            AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            BigInteger serial = new BigInteger(128, new SecureRandom());
            DateTime from = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

            DateTime to = from.AddYears(5);
  

            V3TbsCertificateGenerator tbsGen = new V3TbsCertificateGenerator();
            tbsGen.SetIssuer(issuer.SubjectDN);
            tbsGen.SetSerialNumber(new DerInteger(serial));
            tbsGen.SetStartDate(new Time(from));
            tbsGen.SetEndDate(new Time(to));
            tbsGen.SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(csr.GetPublicKey()));
            tbsGen.SetSubject(csrinfo.Subject);

            // add certificate purposes
            Asn1EncodableVector vector = new Asn1EncodableVector();
            vector.Add(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2"));
            vector.Add(new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.2"));
            vector.Add(new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12"));
            vector.Add(new DerObjectIdentifier("1.3.6.1.5.5.7.3.4"));
            DerSequence seq = new DerSequence(vector);
            X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();
            extGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, seq);

            tbsGen.SetExtensions(extGenerator.Generate());

            tbsGen.SetSignature(sigAlgId);

            TbsCertificateStructure tbsCert = tbsGen.GenerateTbsCertificate();

            // save the TBS
            System.IO.File.WriteAllBytes("tbs.cer", tbsCert.GetDerEncoded());

            Console.WriteLine("generate the signature (SHA->DER->ENCRYPT) for tbs.cer and call it tbs.sig");
            Console.WriteLine("And then press enter");
            Console.ReadLine();

            var t1 = GenerateJcaObject(tbsCert, sigAlgId, System.IO.File.ReadAllBytes("tbs.sig").Take(256).ToArray());

            System.IO.File.WriteAllBytes("cert.cer", t1.GetEncoded());

            Console.WriteLine("saved as cert.cer");
        }

        public static void SignCert(string tbsfile, string tbssig)
        {
            AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption);



            var t1 = GenerateJcaObject(
                TbsCertificateStructure.GetInstance(Asn1Sequence.FromByteArray(File.ReadAllBytes(tbsfile))), sigAlgId,
                System.IO.File.ReadAllBytes(tbssig).Take(256).ToArray());

            System.IO.File.WriteAllBytes("cert.cer", t1.GetEncoded());

            Console.WriteLine("saved as cert.cer");
        }

        public static AsymmetricCipherKeyPair ReadAsymmetricKeyParameter(string pemFilename)
        {
            var fileStream = System.IO.File.OpenText(pemFilename);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(fileStream);
            var KeyParameter = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)pemReader.ReadObject();
            return KeyParameter;
        }

        public static void SelfSign(string privateKey, string csrFile)
        {
            var pk = ReadAsymmetricKeyParameter(privateKey);

            var PKKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pk.Private);

            var reader = new PemReader(File.OpenText(csrFile));

            var csr = (Pkcs10CertificationRequest)(reader.ReadObject());
            var csrinfo = csr.GetCertificationRequestInfo();

            AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            BigInteger serial = new BigInteger(128, new SecureRandom());
            DateTime from = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

            DateTime to = from.AddYears(20);


            X509V3CertificateGenerator tbsGen = new X509V3CertificateGenerator();
            tbsGen.SetIssuerDN(csrinfo.Subject);
            tbsGen.SetSerialNumber(serial);
            tbsGen.SetNotBefore((from));
            tbsGen.SetNotAfter((to));
            tbsGen.SetPublicKey(csr.GetPublicKey());
            tbsGen.SetSubjectDN(csrinfo.Subject);

            tbsGen.SetSignatureAlgorithm("SHA256WITHRSA");

            var cert = tbsGen.Generate(pk.Private);

            // save the TBS
            System.IO.File.WriteAllBytes("cert.cer", cert.GetEncoded());

            
        }

        static X509Certificate GenerateJcaObject(
    TbsCertificateStructure tbsCert,
    AlgorithmIdentifier sigAlg,
    byte[] signature)
        {
            return new X509Certificate(
                new X509CertificateStructure(tbsCert, sigAlg, new DerBitString(signature)));
        }
    }
}
