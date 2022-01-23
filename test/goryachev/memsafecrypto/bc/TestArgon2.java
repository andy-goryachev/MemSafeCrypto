// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.common.util.D;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.TUtils;


/**
 * Tests Argon2.
 * 
 * @see https://www.rfc-editor.org/rfc/rfc9106.html
 */
public class TestArgon2
{
	private static final boolean BENCHMARK = true;
	
	
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	protected static String getType(int x)
	{
		switch(x)
		{
		case Argon2Parameters.ARGON2_d:
			return "argon2d";
		case Argon2Parameters.ARGON2_i:
			return "argon2i";
		case Argon2Parameters.ARGON2_id:
			return "argon2id";
		}
		throw new Error("?" + x);
	}
	
	
	/*
	Test results on a 24-core system with Xeon X5650 2.67GHz:

	TestArgon2.t:143 elapsed=0.29 (bc=0.19) type=argon2d mem=64MB lanes=1
	TestArgon2.t:143 elapsed=0.28 (bc=0.12) type=argon2d mem=64MB lanes=4
	TestArgon2.t:143 elapsed=0.29 (bc=0.12) type=argon2d mem=64MB lanes=48
	TestArgon2.t:143 elapsed=2.35 (bc=1.50) type=argon2d mem=512MB lanes=1
	TestArgon2.t:143 elapsed=2.31 (bc=1.73) type=argon2d mem=512MB lanes=4
	TestArgon2.t:143 elapsed=2.95 (bc=0.99) type=argon2d mem=512MB lanes=48
	TestArgon2.t:143 elapsed=13.29 (bc=6.96) type=argon2d mem=2000MB lanes=1
	TestArgon2.t:143 elapsed=11.60 (bc=7.58) type=argon2d mem=2000MB lanes=4
	TestArgon2.t:143 elapsed=14.23 (bc=5.56) type=argon2d mem=2000MB lanes=48
	TestArgon2.t:143 elapsed=0.36 (bc=0.11) type=argon2i mem=64MB lanes=1
	TestArgon2.t:143 elapsed=0.35 (bc=0.12) type=argon2i mem=64MB lanes=4
	TestArgon2.t:143 elapsed=0.37 (bc=0.12) type=argon2i mem=64MB lanes=48
	TestArgon2.t:143 elapsed=2.39 (bc=1.75) type=argon2i mem=512MB lanes=1
	TestArgon2.t:143 elapsed=2.39 (bc=1.92) type=argon2i mem=512MB lanes=4
	TestArgon2.t:143 elapsed=2.34 (bc=1.72) type=argon2i mem=512MB lanes=48
	TestArgon2.t:143 elapsed=11.23 (bc=6.70) type=argon2i mem=2000MB lanes=1
	TestArgon2.t:143 elapsed=11.53 (bc=6.35) type=argon2i mem=2000MB lanes=4
	TestArgon2.t:143 elapsed=11.04 (bc=7.45) type=argon2i mem=2000MB lanes=48
	TestArgon2.t:143 elapsed=0.37 (bc=0.12) type=argon2id mem=64MB lanes=1
	TestArgon2.t:143 elapsed=0.37 (bc=0.14) type=argon2id mem=64MB lanes=4
	TestArgon2.t:143 elapsed=0.39 (bc=0.14) type=argon2id mem=64MB lanes=48
	TestArgon2.t:143 elapsed=2.49 (bc=0.99) type=argon2id mem=512MB lanes=1
	TestArgon2.t:143 elapsed=2.71 (bc=0.97) type=argon2id mem=512MB lanes=4
	TestArgon2.t:143 elapsed=2.34 (bc=0.97) type=argon2id mem=512MB lanes=48
	TestArgon2.t:143 elapsed=12.56 (bc=6.31) type=argon2id mem=2000MB lanes=1
	TestArgon2.t:143 elapsed=11.84 (bc=8.89) type=argon2id mem=2000MB lanes=4
	TestArgon2.t:143 elapsed=11.01 (bc=6.05) type=argon2id mem=2000MB lanes=48
	*/
	@Test
	public void testArgon() throws Exception
	{
		int[] types = 
		{
			Argon2Parameters.ARGON2_d,
			Argon2Parameters.ARGON2_i,
			Argon2Parameters.ARGON2_id
		};
		
		int[] memKB =
		{
			256_000
//			64_000,
//			512_000,
//			2_000_000
		};
		
		int[] lanes =
		{
//			1,
			4,
//			48 // my machine has 24 cores 
		};
		
		int[] iterations =
		{
			1,
//			2	// linear
		};
		
		for(int type: types)
		{
			for(int mem: memKB)
			{
				for(int iter: iterations)
				{
					for(int lane: lanes)
					{
						t(type, mem, lane, iter);
					}
				}
			}
		}
	}
	
	
	protected void t(int type, int memKB, int lanes, int iterations)
	{
		String[] passwords =
		{
			"",
			"abracadabra !$@!$% 馬鹿外人01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
		};
			
		for(String password: passwords)
		{
			byte[] salt = TUtils.rnd(256/8);
			byte[] pass = password.getBytes(CKit.CHARSET_UTF8);
			
			CByteArray pw = CByteArray.readOnly(pass);
			CByteArray sa = CByteArray.readOnly(salt);
			
			// bc
			org.bouncycastle.crypto.params.Argon2Parameters bp = new org.bouncycastle.crypto.params.Argon2Parameters.Builder(type).
				withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13).
				withMemoryAsKB(memKB).
				withParallelism(lanes).
				withIterations(iterations).
				withSalt(salt).
				build();
			
			byte[] expected = new byte[256/8];

			long start0 = System.nanoTime();
			
			org.bouncycastle.crypto.generators.Argon2BytesGenerator bc = new org.bouncycastle.crypto.generators.Argon2BytesGenerator();
			bc.init(bp);
			bc.generateBytes(pass, expected);

			long elapsed0 = System.nanoTime() - start0;
			
			// memsafe
			goryachev.memsafecrypto.bc.Argon2Parameters mp = new goryachev.memsafecrypto.bc.Argon2Parameters.Builder(type).
				withVersion(goryachev.memsafecrypto.bc.Argon2Parameters.ARGON2_VERSION_13).
				withMemoryAsKB(memKB).
				withParallelism(lanes).
				withIterations(iterations).
				withSalt(sa).
				build();
			
			CByteArray res = new CByteArray(256/8);
			long start = System.nanoTime();
			
			goryachev.memsafecrypto.bc.Argon2BytesGenerator ms = new goryachev.memsafecrypto.bc.Argon2BytesGenerator();
			ms.init(mp);
			ms.generateBytes(pw, res);
			
			long elapsed = System.nanoTime() - start;
			
			if(BENCHMARK && (pass.length > 1000))
			{
				D.print(String.format
				(
					"elapsed=%.2f (bc=%.2f) type=%s mem=%dMB lanes=%d",
					elapsed / 1_000_000_000.0,
					elapsed0 / 1_000_000_000.0,
					getType(type),
					(memKB / 1000),
					lanes
				));
			}
			
			TF.eq(res.toByteArray(), expected);
		}
	}
}
