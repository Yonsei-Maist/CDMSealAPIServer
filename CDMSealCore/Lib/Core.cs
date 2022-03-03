using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.Research.SEAL;

using System.IO;
using System.Security.Cryptography;

namespace CDMSealCore.Lib {
	public class Core {
        static private SEALContext context = null;
        static private KeyGenerator keyGenerator = null;
        static private SecretKey secretKey = null;
        static private PublicKey publicKey = null;
        static private RelinKeys relinKey = null;

        static private SEALContext Context { get{ if (context == null) loadContext(); return context; } }
        static private KeyGenerator Generator { get { if (keyGenerator == null) keyGenerator = new KeyGenerator(Context); return keyGenerator; }}

        static private void loadContext() {
            EncryptionParameters param = new EncryptionParameters(SchemeType.BFV);

            ulong poly_modulus_degree = 4096;
            param.PolyModulusDegree = poly_modulus_degree;
            param.CoeffModulus = CoeffModulus.BFVDefault(poly_modulus_degree);

            param.PlainModulus = new Modulus(1024);
            //param.SetPlainModulus(1024);

            context = new SEALContext(param);
        }

        static private void loadKey() {
            if (secretKey == null || publicKey == null || relinKey == null) {

                KeyManager keyManager = KeyManager.GetInstance();
                string base64SecretKey = keyManager.PrivateKey;
				string base64PublicKey = keyManager.PublicKey;
                string base64RelinKeys = keyManager.RelinKey;

				secretKey = new SecretKey();
                publicKey = new PublicKey();
                relinKey = new RelinKeys();

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(base64SecretKey))) {
                    secretKey.Load(Context, ms);
                }

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(base64PublicKey))) {
                    publicKey.Load(Context, ms);
				}

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(base64RelinKeys))) {
                    relinKey.Load(Context, ms);
				}
            }
		}

        static private Ciphertext loadCipher(string cipher) {
            Ciphertext ciphertext = new Ciphertext();
            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipher))) {
                ciphertext.Load(Context, ms);
            }

            return ciphertext;
        }
        
        static private Plaintext loadPlain(ulong plain) {
            byte[] bytes = BitConverter.GetBytes(plain);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(bytes);
            }

            return new Plaintext(BitConverter.ToString(bytes).Replace("-", ""));
        }

        static private string getStringCipher(Ciphertext ciphertext) {
            string result = "";
            using (MemoryStream ms = new MemoryStream()) {
                ciphertext.Save(ms);

                result = Convert.ToBase64String(ms.ToArray());
            }

            return result;
        }

        static private string getStringPlain(Plaintext plaintext) {
            return plaintext.ToString();
        }

        static public string GetEncryptedCipher(ulong value) {
            loadKey();

            Ciphertext ciphertext = new Ciphertext();
            Plaintext plaintext = loadPlain(value);

            using (Encryptor encryptor = new Encryptor(Context, publicKey)) {
                encryptor.Encrypt(plaintext, ciphertext);
            }

            return getStringCipher(ciphertext);
        }

        static public string GetDecryptedPlain(string cipher) {
            loadKey();

            Ciphertext ciphertext = loadCipher(cipher);
            Plaintext plaintext = new Plaintext();
            using (Decryptor decryptor = new Decryptor(Context, secretKey)) {
                decryptor.Decrypt(ciphertext, plaintext);
            }

            return Convert.ToUInt64(getStringPlain(plaintext), 16).ToString();
        }

        static public string Add(IEnumerable<string> ciphers) {
            List<Ciphertext> ciphertextList = new List<Ciphertext>();

            foreach (string item in ciphers) {
                ciphertextList.Add(loadCipher(item));
            }

            Ciphertext added = new Ciphertext();

            Evaluator evaluator = new Evaluator(Context);
            evaluator.AddMany(ciphertextList, added);

            return getStringCipher(added);
        }

        static public string Multiply(IEnumerable<string> ciphers) {
            List<Ciphertext> ciphertextList = new List<Ciphertext>();

            foreach (string item in ciphers) {
                ciphertextList.Add(loadCipher(item));
            }

            Ciphertext added = new Ciphertext();

            Evaluator evaluator = new Evaluator(Context);
            evaluator.MultiplyMany(ciphertextList, relinKey, added);

            return getStringCipher(added);
        }

        static public string CreatePrivateKey() {

            string result = "";
            using (MemoryStream ms = new MemoryStream()) {

                secretKey = Generator.SecretKey;
                secretKey.Save(ms);
                result = Convert.ToBase64String(ms.ToArray());
            }

            return result;
        }

		static public string CreatePublicKey() {
            PublicKey key = new PublicKey();
            Generator.CreatePublicKey(out key);

            string result = "";
            using (MemoryStream ms = new MemoryStream()) {
                publicKey = key;
                key.Save(ms);
                ms.Seek(0, SeekOrigin.Begin);
                result = Convert.ToBase64String(ms.ToArray());
            }

            return result;
        }

        static public string CreateRelinKey() {
            RelinKeys key = new RelinKeys();

            Generator.CreateRelinKeys(out key);

            string result = "";
            using (MemoryStream ms = new MemoryStream()) {
                key.Save(ms);
                relinKey = key;
                result = Convert.ToBase64String(ms.ToArray());
            }

            return result;
        }
	}

	public class Security {
		static public string SecretKey { get; set; }
        static private SHA256Managed sha256Managed = new SHA256Managed();
        static private RijndaelManaged aes = new RijndaelManaged() {
            KeySize = 256,
            BlockSize = 128,
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7
        };

        static public byte[] AESEncrypt256(byte[] encryptData) {
            byte[] salt = sha256Managed.ComputeHash(Encoding.UTF8.GetBytes(SecretKey.Length.ToString()));

            Rfc2898DeriveBytes PBKDF2Key = new Rfc2898DeriveBytes(SecretKey, salt, 65535, HashAlgorithmName.SHA256);
            byte[] secretKey = PBKDF2Key.GetBytes(aes.KeySize / 8);
            byte[] iv = PBKDF2Key.GetBytes(aes.BlockSize / 8);

            byte[] xBuff = null;
            using (MemoryStream ms = new MemoryStream()) {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(secretKey, iv), CryptoStreamMode.Write)) {
                    cs.Write(encryptData, 0, encryptData.Length);
                }

                xBuff = ms.ToArray();
            }

            return xBuff;
        }

        static public byte[] AESDecrypt256(byte[] decryptData) {
            byte[] salt = sha256Managed.ComputeHash(Encoding.UTF8.GetBytes(SecretKey.Length.ToString()));

            Rfc2898DeriveBytes PBKDF2Key = new Rfc2898DeriveBytes(SecretKey, salt, 65535, HashAlgorithmName.SHA256);
            byte[] secretKey = PBKDF2Key.GetBytes(aes.KeySize / 8);
            byte[] iv = PBKDF2Key.GetBytes(aes.BlockSize / 8);

            byte[] xBuff = null;
            using (MemoryStream ms = new MemoryStream()) {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(secretKey, iv), CryptoStreamMode.Write)) {
                    cs.Write(decryptData, 0, decryptData.Length);
                }

                xBuff = ms.ToArray();
            }

            return xBuff;
        }
    }

	public class KeyManager {
        static private string Separator = "\n///SEPARATOR///\n";
		static private KeyManager instance = null;
		public string PrivateKey { get; set; }
		public string PublicKey { get; set; }
        public string RelinKey { get; set; }

		static public KeyManager GetInstance() {
			if (instance == null)
                instance = new KeyManager();

			return instance;
		}

		private KeyManager() {

		}

		public void ReadKey(string path) {
            try {
                byte[] content = File.ReadAllBytes(path);
                byte[] dec = Security.AESDecrypt256(content);
                string decryption = Encoding.UTF8.GetString(dec);

                string[] keys = decryption.Split(Separator);
                PrivateKey = keys[0];
                PublicKey = keys[1];
                RelinKey = keys[2];
            } catch {
                CreateKey(path);
			}
		}

		public void CreateKey(string path) {
			PrivateKey = Core.CreatePrivateKey();
			PublicKey = Core.CreatePublicKey();
            RelinKey = Core.CreateRelinKey();

            File.WriteAllBytes(path, Security.AESEncrypt256(Encoding.UTF8.GetBytes(PrivateKey + Separator + PublicKey + Separator + RelinKey)));
		}
	}
}
