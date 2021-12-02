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
		int count = 500;
		int size = 10_000;
		
		for(int i=0; i<count; i++)
		{
			CByteArray key = TUtils.rndByteArray(XSalsaTools.KEY_LENGTH_BYTES);
			CByteArray nonce = TUtils.rndByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
			CByteArray data = TUtils.rndByteArray(size);
			
			CByteArray os = new CByteArray(size);
			XSalsaTools.encrypt(key, nonce, data, os, 0, data.length());
			
			CByteArray encrypted = os.toReadOnly();
			
			CByteArray decrypted = new CByteArray(size); 

			XSalsaTools.decrypt(key, nonce, 0, encrypted.length(), encrypted, decrypted);
			
			TF.eq(decrypted.toByteArray(), data.toByteArray());
		}
	}
}
