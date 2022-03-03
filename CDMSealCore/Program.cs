using CDMSealCore.Lib;
using Microsoft.Research.SEAL;
using System;

namespace CDMSealCore {
	class Program {
		static void Main(string[] args) {
			Security.SecretKey = "MAIST-FHE2021";
			SealManager manager = new SealManager(@"D:\document\cdm\ir_summary.csv", @"D:\document\cdm\result.txt", @"D:\document\임시\FHE\key.txt");

			manager.doTest();
		}
	}
}
