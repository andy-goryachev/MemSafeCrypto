// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;


/**
 * Tests SHA256Digest.
 */
public class TestSHA256Digest
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void testEncrypt() throws Exception
	{
		int maxLen = 1_111;
		int bits = 256;
		
		for(int len=0; len<maxLen; len++)
		{
			byte[] data = TUtils.rnd(len);
			CByteArray data2 = CByteArray.readOnly(data);
			
			org.bouncycastle.crypto.digests.SHA256Digest bc = new org.bouncycastle.crypto.digests.SHA256Digest();
			bc.update(data, 0, data.length);
			byte[] expected = new byte[bits/8];
			bc.doFinal(expected, 0);

			goryachev.memsafecrypto.bc.SHA256Digest b1 = new goryachev.memsafecrypto.bc.SHA256Digest();
			b1.update(data, 0, data.length);
			byte[] r1 = new byte[bits/8];
			b1.doFinal(r1, 0);
			
			goryachev.memsafecrypto.bc.SHA256Digest b2 = new goryachev.memsafecrypto.bc.SHA256Digest();
			b2.update(data, 0, data.length);
			CByteArray r2 = new CByteArray(bits/8);
			b2.doFinal(r2, 0);
			
			goryachev.memsafecrypto.bc.SHA256Digest b3 = new goryachev.memsafecrypto.bc.SHA256Digest();
			b3.update(data2, 0, data2.length());
			CByteArray r3 = new CByteArray(bits/8);
			b3.doFinal(r3, 0);
			
			TF.eq(r1, expected);
			TF.eq(r2.toByteArray(), expected);
			TF.eq(r3.toByteArray(), expected);
		}
	}
}
