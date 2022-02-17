using System;
using System.Security.Cryptography;
using System.Text;

namespace SigningDemo
{
    class Program
    {

        CngKey _aliceKeySignature;
        private byte[] _alicePubKeyBlob;

        static void Main()
        {
            var p = new Program();
            p.Run();
        }

        public void Run()
        {
            InitAliceKeys();

            byte[] aliceData = Encoding.UTF8.GetBytes("Alice");
            byte[] aliceSignature = CreateSignature(aliceData, _aliceKeySignature);
            Console.WriteLine($"Alice created signature: {Convert.ToBase64String(aliceSignature)}");

            if (VerifySignature(aliceData, aliceSignature, _alicePubKeyBlob))
            {
                Console.WriteLine("Alice signature verified successfully");
            }
        }

        public void InitAliceKeys()
        {
            //create a key pair and export public key into a blob
            _aliceKeySignature = CngKey.Create(CngAlgorithm.ECDsaP521);
            _alicePubKeyBlob = _aliceKeySignature.Export(CngKeyBlobFormat.GenericPublicBlob);
        }

        private byte[] CreateSignature(byte[] data, CngKey key)
        {
            // alice's name data element is signed using alice's private key
            byte[] signature;
            using (var signingAlg = new ECDsaCng(key))
            {
                signature = signingAlg.SignData(data, HashAlgorithmName.SHA512);
                signingAlg.Clear();
            }
            return signature;
        }

        private bool VerifySignature(byte[] data, byte[] signature, byte[] pubKey)
        {
            // import key blob to obtain public key
            // create new crypto class instance and use it to
            // check that signature is indeed that of alice's
            bool retValue = false;
            using (CngKey key = CngKey.Import(pubKey, CngKeyBlobFormat.GenericPublicBlob))
            using (var signingAlg = new ECDsaCng(key))
            {
                retValue = signingAlg.VerifyData(data, signature, HashAlgorithmName.SHA512);
                signingAlg.Clear();
            }
            return retValue;
        }
    }
}
