using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace CDMSealCore.Lib {
	public class SealManager {
		private KeyManager keyManager = KeyManager.GetInstance();
		private string readPath;
		private string keyPath;
		private string[] contentList;

		public SealManager(string readPath, string keyPath) {
			this.readPath = readPath;
			this.keyPath = keyPath;
		}

		public void doTest() {
			this.contentList = File.ReadAllLines(this.readPath);
			this.keyManager.ReadKey(this.keyPath);

			List<string> encryptedList = new List<string>();
			ulong addedNonEncryted = 0;

			foreach(string item in this.contentList) {
				ulong output;
				bool res = ulong.TryParse(item, out output);
				if (res) {
					string encrypted = Core.GetEncryptedCipher(output);
					encryptedList.Add(encrypted);
					addedNonEncryted += output;

					Console.WriteLine("Origin Value: {0}, Encrypted Value: {1}", item, encrypted.Length);
				}
			}

			string added = Core.Add(encryptedList);
			string decrypted = Core.GetDecryptedPlain(added);

			Console.WriteLine("Sum of values: {0}, Sum of FHE: {1}, Decrypted of Sum of FHE: {2}", addedNonEncryted, added.Length, decrypted);
		}
	}
}
