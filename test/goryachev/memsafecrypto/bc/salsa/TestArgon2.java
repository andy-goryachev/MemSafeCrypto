// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.common.util.Hex;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.TUtils;


/**
 * Tests Argon2.
 */
public class TestArgon2
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void testArgon() throws Exception
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
			int N = 1024;
			int r = 8;
			int p = 32;
			int dkLen = 256/8;
			byte[] salt = TUtils.rnd(256/8);
			
			TF.print("password=", password, "N=", N, "r=", r, "p=", p, "dkLen=", dkLen, "salt=", Hex.toHexString(salt));

			byte[] pass = password.getBytes(CKit.CHARSET_UTF8);
			
			CByteArray pw = CByteArray.readOnly(pass);
			CByteArray sa = CByteArray.readOnly(salt);
			
			// bc
			org.bouncycastle.crypto.params.Argon2Parameters bp = new org.bouncycastle.crypto.params.Argon2Parameters.Builder().
				withSalt(salt).
				build();
			
			byte[] expected = new byte[256/8];
			org.bouncycastle.crypto.generators.Argon2BytesGenerator bc = new org.bouncycastle.crypto.generators.Argon2BytesGenerator();
			bc.init(bp);
			bc.generateBytes(pass, expected);
			
			// memsafe
			goryachev.memsafecrypto.bc.Argon2Parameters mp = new goryachev.memsafecrypto.bc.Argon2Parameters.Builder().
				withSalt(sa).
				build();
			
			CByteArray res = new CByteArray(256/8);
			goryachev.memsafecrypto.bc.Argon2BytesGenerator ms = new goryachev.memsafecrypto.bc.Argon2BytesGenerator();
			ms.init(mp);
			ms.generateBytes(pw, res);
			
			TF.eq(res.toByteArray(), expected);
		}
	}
}
