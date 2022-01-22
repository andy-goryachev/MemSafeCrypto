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
			64_000,
			512_000,
			2_000_000
		};
		
		int[] lanes =
		{
			1,
			2,
			4,
			8,
			16,
			24,
			48,
			96
		};
		
		int[] iterations =
		{
			1,
			2
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
			"a",
			"abracadabra !$@!$% 馬鹿外人",
			"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
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
			
			if(BENCHMARK)
			{
				D.print(String.format
				(
					"elapsed=%.2f (bc=%.2f) type=%s mem=%dMB lanes=%d iterations=%d",
					elapsed / 1_000_000_000.0,
					elapsed0 / 1_000_000_000.0,
					getType(type),
					(memKB / 1000),
					lanes,
					iterations
				));
			}
			
			TF.eq(res.toByteArray(), expected);
		}
	}
}
