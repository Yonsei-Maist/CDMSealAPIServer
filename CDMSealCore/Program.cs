using CDMSealCore.Lib;
using Microsoft.Research.SEAL;
using System;

namespace CDMSealCore {
	class Program {
		public static string ULongToString(ulong value) {
			byte[] bytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(bytes);
			}
			return BitConverter.ToString(bytes).Replace("-", "");
		}

		private static void ExampleBFVBasics() {
			Console.WriteLine("Example: BFV Basics");
			using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
			
			ulong polyModulusDegree = 4096;
			parms.PolyModulusDegree = polyModulusDegree;

			parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);

			parms.PlainModulus = new Modulus(1024);
			using SEALContext context = new SEALContext(parms);

			Console.WriteLine();
			Console.WriteLine("Set encryption parameters and print");
			Console.WriteLine(context);

			Console.WriteLine("Parameter validation (success): {0}", context.ParameterErrorMessage());

			Console.WriteLine();
			Console.WriteLine("~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~");

			using KeyGenerator keygen = new KeyGenerator(context);
			using SecretKey secretKey = keygen.SecretKey;
			keygen.CreatePublicKey(out PublicKey publicKey);

			using Encryptor encryptor = new Encryptor(context, publicKey);

			using Evaluator evaluator = new Evaluator(context);

			using Decryptor decryptor = new Decryptor(context, secretKey);

			Console.WriteLine();
			ulong x = 12;
			using Plaintext xPlain = new Plaintext(ULongToString(x));
			using Plaintext xPlain2 = new Plaintext(ULongToString(x));
			Console.WriteLine($"Express x = {x} as a plaintext polynomial 0x{xPlain}.");

			Console.WriteLine();
			using Ciphertext xEncrypted = new Ciphertext();
			using Ciphertext xEncrypted2 = new Ciphertext();
			Console.WriteLine("Encrypt xPlain to xEncrypted.");
			encryptor.Encrypt(xPlain, xEncrypted);
			encryptor.Encrypt(xPlain2, xEncrypted2);
			using Ciphertext ttt = new Ciphertext();
			evaluator.Add(xEncrypted, xEncrypted2, ttt);

			Console.WriteLine($"    + size of xSqPlusOne: {ttt.Size}");
			Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
				decryptor.InvariantNoiseBudget(ttt));

			using Plaintext decryptedResult22 = new Plaintext();
			Console.Write("    + decryption of xSqPlusOne: ");
			decryptor.Decrypt(ttt, decryptedResult22);
			Console.WriteLine($"0x{decryptedResult22} ...... Correct.");

			/*
			In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
			whose coefficients are integers modulo the product of the primes in the
			coeff_modulus. The number of polynomials in a ciphertext is called its `size'
			and is given by Ciphertext.Size. A freshly encrypted ciphertext always has
			size 2.
			*/
			Console.WriteLine($"    + size of freshly encrypted x: {xEncrypted.Size}");

			/*
			There is plenty of noise budget left in this freshly encrypted ciphertext.
			*/
			Console.WriteLine("    + noise budget in freshly encrypted x: {0} bits",
				decryptor.InvariantNoiseBudget(xEncrypted));

			/*
			We decrypt the ciphertext and print the resulting plaintext in order to
			demonstrate correctness of the encryption.
			*/
			using Plaintext xDecrypted = new Plaintext();
			Console.Write("    + decryption of encrypted_x: ");
			decryptor.Decrypt(xEncrypted, xDecrypted);
			Console.WriteLine($"0x{xDecrypted} ...... Correct.");

			/*
			When using Microsoft SEAL, it is typically advantageous to compute in a way
			that minimizes the longest chain of sequential multiplications. In other
			words, encrypted computations are best evaluated in a way that minimizes
			the multiplicative depth of the computation, because the total noise budget
			consumption is proportional to the multiplicative depth. For example, for
			our example computation it is advantageous to factorize the polynomial as
				4x^4 + 8x^3 + 8x^2 + 8x + 4 = 4(x + 1)^2 * (x^2 + 1)
			to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
			(x^2 + 1) separately, before multiplying them, and multiplying by 4.
			First, we compute x^2 and add a plaintext "1". We can clearly see from the
			print-out that multiplication has consumed a lot of noise budget. The user
			can vary the plain_modulus parameter to see its effect on the rate of noise
			budget consumption.
			*/
			Console.WriteLine();
			Console.WriteLine("Compute xSqPlusOne (x^2+1).");
			using Ciphertext xSqPlusOne = new Ciphertext();
			evaluator.Square(xEncrypted, xSqPlusOne);
			using Plaintext plainOne = new Plaintext("1");
			evaluator.AddPlainInplace(xSqPlusOne, plainOne);

			/*
			Encrypted multiplication results in the output ciphertext growing in size.
			More precisely, if the input ciphertexts have size M and N, then the output
			ciphertext after homomorphic multiplication will have size M+N-1. In this
			case we perform a squaring, and observe both size growth and noise budget
			consumption.
			*/
			Console.WriteLine($"    + size of xSqPlusOne: {xSqPlusOne.Size}");
			Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
				decryptor.InvariantNoiseBudget(xSqPlusOne));

			/*
			Even though the size has grown, decryption works as usual as long as noise
			budget has not reached 0.
			*/
			using Plaintext decryptedResult = new Plaintext();
			Console.Write("    + decryption of xSqPlusOne: ");
			decryptor.Decrypt(xSqPlusOne, decryptedResult);
			Console.WriteLine($"0x{decryptedResult} ...... Correct.");

			/*
			Next, we compute (x + 1)^2.
			*/
			Console.WriteLine();
			Console.WriteLine("Compute xPlusOneSq ((x+1)^2).");
			using Ciphertext xPlusOneSq = new Ciphertext();
			evaluator.AddPlain(xEncrypted, plainOne, xPlusOneSq);
			evaluator.SquareInplace(xPlusOneSq);
			Console.WriteLine($"    + size of xPlusOneSq: {xPlusOneSq.Size}");
			Console.WriteLine("    + noise budget in xPlusOneSq: {0} bits",
				decryptor.InvariantNoiseBudget(xPlusOneSq));
			Console.Write("    + decryption of xPlusOneSq: ");
			decryptor.Decrypt(xPlusOneSq, decryptedResult);
			Console.WriteLine($"0x{decryptedResult} ...... Correct.");

			/*
			Finally, we multiply (x^2 + 1) * (x + 1)^2 * 4.
			*/
			Console.WriteLine();
			Console.WriteLine("Compute encryptedResult (4(x^2+1)(x+1)^2).");
			using Ciphertext encryptedResult = new Ciphertext();
			using Plaintext plainFour = new Plaintext("4");
			evaluator.MultiplyPlainInplace(xSqPlusOne, plainFour);
			evaluator.Multiply(xSqPlusOne, xPlusOneSq, encryptedResult);
			Console.WriteLine($"    + size of encrypted_result: {encryptedResult.Size}");
			Console.WriteLine("    + noise budget in encrypted_result: {0} bits",
				decryptor.InvariantNoiseBudget(encryptedResult));
			Console.WriteLine("NOTE: Decryption can be incorrect if noise budget is zero.");

			Console.WriteLine();
			Console.WriteLine("~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~");

			/*
			Noise budget has reached 0, which means that decryption cannot be expected
			to give the correct result. This is because both ciphertexts xSqPlusOne and
			xPlusOneSq consist of 3 polynomials due to the previous squaring operations,
			and homomorphic operations on large ciphertexts consume much more noise budget
			than computations on small ciphertexts. Computing on smaller ciphertexts is
			also computationally significantly cheaper.
			`Relinearization' is an operation that reduces the size of a ciphertext after
			multiplication back to the initial size, 2. Thus, relinearizing one or both
			input ciphertexts before the next multiplication can have a huge positive
			impact on both noise growth and performance, even though relinearization has
			a significant computational cost itself. It is only possible to relinearize
			size 3 ciphertexts down to size 2, so often the user would want to relinearize
			after each multiplication to keep the ciphertext sizes at 2.
			Relinearization requires special `relinearization keys', which can be thought
			of as a kind of public key. Relinearization keys can easily be created with
			the KeyGenerator.
			Relinearization is used similarly in both the BFV and the CKKS schemes, but
			in this example we continue using BFV. We repeat our computation from before,
			but this time relinearize after every multiplication.
			*/
			Console.WriteLine();
			Console.WriteLine("Generate locally usable relinearization keys.");
			keygen.CreateRelinKeys(out RelinKeys relinKeys);

			/*
			We now repeat the computation relinearizing after each multiplication.
			*/
			Console.WriteLine();
			Console.WriteLine("Compute and relinearize xSquared (x^2),");
			Console.WriteLine(new string(' ', 13) + "then compute xSqPlusOne (x^2+1)");
			using Ciphertext xSquared = new Ciphertext();
			evaluator.Square(xEncrypted, xSquared);
			Console.WriteLine($"    + size of xSquared: {xSquared.Size}");
			evaluator.RelinearizeInplace(xSquared, relinKeys);
			Console.WriteLine("    + size of xSquared (after relinearization): {0}",
				xSquared.Size);
			evaluator.AddPlain(xSquared, plainOne, xSqPlusOne);
			Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
				decryptor.InvariantNoiseBudget(xSqPlusOne));
			Console.Write("    + decryption of xSqPlusOne: ");
			decryptor.Decrypt(xSqPlusOne, decryptedResult);
			Console.WriteLine($"0x{decryptedResult} ...... Correct.");

			Console.WriteLine();
			using Ciphertext xPlusOne = new Ciphertext();
			Console.WriteLine("Compute xPlusOne (x+1),");
			Console.WriteLine(new string(' ', 13) +
				"then compute and relinearize xPlusOneSq ((x+1)^2).");
			evaluator.AddPlain(xEncrypted, plainOne, xPlusOne);
			evaluator.Square(xPlusOne, xPlusOneSq);
			Console.WriteLine($"    + size of xPlusOneSq: {xPlusOneSq.Size}");
			evaluator.RelinearizeInplace(xPlusOneSq, relinKeys);
			Console.WriteLine("    + noise budget in xPlusOneSq: {0} bits",
				decryptor.InvariantNoiseBudget(xPlusOneSq));
			Console.Write("    + decryption of xPlusOneSq: ");
			decryptor.Decrypt(xPlusOneSq, decryptedResult);
			Console.WriteLine($"0x{decryptedResult} ...... Correct.");

			Console.WriteLine();
			Console.WriteLine("Compute and relinearize encryptedResult (4(x^2+1)(x+1)^2).");
			evaluator.MultiplyPlainInplace(xSqPlusOne, plainFour);
			evaluator.Multiply(xSqPlusOne, xPlusOneSq, encryptedResult);
			Console.WriteLine($"    + size of encryptedResult: {encryptedResult.Size}");
			evaluator.RelinearizeInplace(encryptedResult, relinKeys);
			Console.WriteLine("    + size of encryptedResult (after relinearization): {0}",
				encryptedResult.Size);
			Console.WriteLine("    + noise budget in encryptedResult: {0} bits",
				decryptor.InvariantNoiseBudget(encryptedResult));

			Console.WriteLine();
			Console.WriteLine("NOTE: Notice the increase in remaining noise budget.");

			/*
			Relinearization clearly improved our noise consumption. We have still plenty
			of noise budget left, so we can expect the correct answer when decrypting.
			*/
			Console.WriteLine();
			Console.WriteLine("Decrypt encrypted_result (4(x^2+1)(x+1)^2).");
			decryptor.Decrypt(encryptedResult, decryptedResult);
			Console.WriteLine("    + decryption of 4(x^2+1)(x+1)^2 = 0x{0} ...... Correct.",
				decryptedResult);

			/*
			For x=6, 4(x^2+1)(x+1)^2 = 7252. Since the plaintext modulus is set to 1024,
			this result is computed in integers modulo 1024. Therefore the expected output
			should be 7252 % 1024 == 84, or 0x54 in hexadecimal.
			*/

			/*
			Sometimes we create customized encryption parameters which turn out to be invalid.
			Microsoft SEAL can interpret the reason why parameters are considered invalid.
			Here we simply reduce the polynomial modulus degree to make the parameters not
			compliant with the HomomorphicEncryption.org security standard.
			*/
			Console.WriteLine();
			Console.WriteLine("An example of invalid parameters");
			parms.PolyModulusDegree = 2048;
			using SEALContext new_context = new SEALContext(parms);
			//Utilities.PrintParameters(context);
			Console.WriteLine("Parameter validation (failed): {0}", new_context.ParameterErrorMessage());
			Console.WriteLine();

			/*
			This information is helpful to fix invalid encryption parameters.
			*/
		}
		static void Main(string[] args) {
			Security.SecretKey = "MAIST-FHE2021";
			SealManager manager = new SealManager(@"D:\document\임시\FHE\test.txt", @"D:\document\임시\FHE\key.txt");

			manager.doTest();
			//ExampleBFVBasics();
		}
	}
}
