using CDMSealCore.Lib;
using Microsoft.Research.SEAL;
using System;

namespace CDMSealCore {
	class Program {
		static void Main(string[] args) {
			Security.SecretKey = "MAIST-FHE2021";
			SealManager manager = new SealManager(@"D:\document\임시\FHE\test.txt", @"D:\document\임시\FHE\key.txt");

			manager.doTest();
		}
	}
}
