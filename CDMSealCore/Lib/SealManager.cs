using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace CDMSealCore.Lib {
	public class SealManager {
		private KeyManager keyManager = KeyManager.GetInstance();
		private string readPath;
		private string keyPath;
		private string writePath;
		private string[] contentList;

		public SealManager(string readPath, string writePath, string keyPath) {
			this.readPath = readPath;
			this.writePath = writePath;
			this.keyPath = keyPath;
		}

		public void doTest() {
			this.contentList = File.ReadAllLines(this.readPath);
			this.keyManager.ReadKey(this.keyPath);

			List<string> encryptedList = new List<string>();
			ulong addedNonEncryted = 0;

			string writeContent = "db_id, target_id, cases, length of encrypted value, encrypted value, decrypted value\n";

			foreach(string item in this.contentList) {
				string[] splited = item.Split(',');
				string value = splited[5].Replace("\"", "");

				ulong output;
				bool res = ulong.TryParse(value, out output);
				if (res) {
					string encrypted = Core.GetEncryptedCipher(output);
					encryptedList.Add(encrypted);
					addedNonEncryted += output;

					Console.WriteLine("Origin Value: {0}, Length of Encrypted Value: {1}", value, encrypted.Length);
					writeContent += string.Format("{0},{1},{2},{3},{4},-\n", splited[0], splited[1], value, encrypted.Length, encrypted.Replace("\n", ""));
				}
			}

			string added = Core.Add(encryptedList);
			string decrypted = Core.GetDecryptedPlain(added);

			Console.WriteLine("Sum of values: {0}, Sum of FHE: {1}, Decrypted of Sum of FHE: {2}", addedNonEncryted, added.Length, decrypted);

			writeContent += string.Format("sum,-,-,{0},{1}, {2}\n", added.Length, added, decrypted);

			File.WriteAllText(writePath, writeContent);
		}
	}
}
