// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
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
		int maxLen = 2_000;
		
		for(int len=0; len<maxLen; len++)
		{
			byte[] buf = TestUtils.rnd(len);
			
			for(int bits=8; bits<=512; bits += 8)
			{
				goryachev.memsafecrypto.bc.Blake2bDigest b1 = new goryachev.memsafecrypto.bc.Blake2bDigest(bits);
				b1.update(buf, 0, buf.length);
				byte[] d1 = new byte[bits/8];
				b1.doFinal(d1, 0);
				
				org.bouncycastle.crypto.digests.Blake2bDigest b2 = new org.bouncycastle.crypto.digests.Blake2bDigest(bits);
				b2.update(buf, 0, buf.length);
				byte[] d2 = new byte[bits/8];
				b2.doFinal(d2, 0);
				
				goryachev.memsafecrypto.bc.Blake2bDigest b3 = new goryachev.memsafecrypto.bc.Blake2bDigest(bits);
				b3.update(buf, 0, buf.length);
				CByteArray d3 = new CByteArray(bits/8);
				b3.doFinal(d3, 0);
				
				TF.eq(d1, d2);
				TF.eq(d3.toByteArray(), d2);
			}
		}
	}
}
