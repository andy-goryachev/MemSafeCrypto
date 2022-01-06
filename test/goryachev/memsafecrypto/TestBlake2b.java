// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;


/**
 * Tests Blake2bDigest.
 */
public class TestBlake2b
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void testEncrypt() throws Exception
	{
		int maxLen = 1_111;
		
		for(int len=0; len<maxLen; len++)
		{
			byte[] data = TUtils.rnd(len);
			CByteArray data2 = CByteArray.readOnly(data);
			
			for(int bits=8; bits<=512; bits += 8)
			{
				org.bouncycastle.crypto.digests.Blake2bDigest bc = new org.bouncycastle.crypto.digests.Blake2bDigest(bits);
				bc.update(data, 0, data.length);
				byte[] expected = new byte[bits/8];
				bc.doFinal(expected, 0);

				goryachev.memsafecrypto.bc.Blake2bDigest b1 = new goryachev.memsafecrypto.bc.Blake2bDigest(bits);
				b1.update(data, 0, data.length);
				byte[] r1 = new byte[bits/8];
				b1.doFinal(r1, 0);
				
				goryachev.memsafecrypto.bc.Blake2bDigest b2 = new goryachev.memsafecrypto.bc.Blake2bDigest(bits);
				b2.update(data, 0, data.length);
				CByteArray r2 = new CByteArray(bits/8);
				b2.doFinal(r2, 0);
				
				goryachev.memsafecrypto.bc.Blake2bDigest b3 = new goryachev.memsafecrypto.bc.Blake2bDigest(bits);
				b3.update(data2, 0, data2.length());
				CByteArray r3 = new CByteArray(bits/8);
				b3.doFinal(r3, 0);
				
				TF.eq(r1, expected);
				TF.eq(r2.toByteArray(), expected);
				TF.eq(r3.toByteArray(), expected);
			}
		}
	}
}
