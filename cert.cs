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

namespace test
{
    internal class Program
    {
        private static void Main(string[] args)
        {
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

            tbsGen.SetSignature(sigAlgId);

            TbsCertificateStructure tbsCert = tbsGen.GenerateTbsCertificate();

            // save the TBS
            System.IO.File.WriteAllBytes("tbs.cer", tbsCert.GetEncoded());

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
                System.IO.File.ReadAllBytes(tbssig).ToArray());

            System.IO.File.WriteAllBytes("cert.cer", t1.GetEncoded());

            Console.WriteLine("saved as cert.cer");
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
