// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.TUtils;
import goryachev.memsafecrypto.salsa.XSalsaTools;


/**
 * Tests XSalsa20 Tools encryption / decryption.
 */
public class TestXSalsaTools
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void testEncrypt() throws Exception
	{
		int count = 10;
		int maxSize = 100_000;
		
		for(int i=0; i<count; i++)
		{
			for(int size=0; size<maxSize; size += step(size))
			{
				CByteArray key = TUtils.rndByteArray(XSalsaTools.KEY_LENGTH_BYTES);
				CByteArray nonce = TUtils.rndByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
				CByteArray data = TUtils.rndByteArray(size);
				
				// with CByteArray
				
				CByteArray os = new CByteArray(size);
				XSalsaTools.encryptXSalsa20(key, nonce, data, os, 0, data.length());
				CByteArray encrypted = os.toReadOnly();
				
				CByteArray decrypted = new CByteArray(size); 
				XSalsaTools.decryptXSalsa20(key, nonce, 0, encrypted.length(), encrypted, decrypted);
				
				TF.eq(decrypted.toByteArray(), data.toByteArray());
				
				// with byte[]
				
				byte[] os2 = new byte[size];
				XSalsaTools.encryptXSalsa20(key, nonce.toByteArray(), 0, nonce.length(), data, os2, 0);
				
				TF.eq(os2, encrypted.toByteArray());
				
				CByteArray decrypted2 = XSalsaTools.decryptXSalsa20(key, nonce.toByteArray(), 0, nonce.length(), os2, 0, os2.length);
				
				TF.eq(decrypted2.toByteArray(), data.toByteArray());
				
				// with MAC
				
				CByteArray encrypted3 = XSalsaTools.encryptXSalsa20Poly1305(key, nonce, data);
				CByteArray decrypted3 = XSalsaTools.decryptXSalsa20Poly1305(key, nonce, encrypted3);
				
				TF.eq(decrypted3.toByteArray(), data.toByteArray());
			}
		}
	}
	
	
	protected static int step(int size)
	{
		if(size < 16)
		{
			return 1;
		}
		else if(size < 128)
		{
			return 10;
		}
		else
		{
			return 1000;
		}
	}
}
