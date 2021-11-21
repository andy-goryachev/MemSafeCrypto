// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.memsafecrypto.salsa.XSalsaTools;


/**
 * Tests XSalsa20 Streams.
 */
public class TestXSalsa20Streams
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
			CByteArray key = TestUtils.rndByteArray(XSalsaTools.KEY_LENGTH_BYTES);
			CByteArray nonce = TestUtils.rndByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
			CByteArray data = TestUtils.rndByteArray(size);
			
			CByteArray os = new CByteArray(size);
			goryachev.memsafecrypto.salsa.XSalsa20EncryptStream out = new goryachev.memsafecrypto.salsa.XSalsa20EncryptStream(key, nonce, os);
			out.write(data);
			out.close();
			
			CByteArray encrypted = os.toReadOnly();
			
			goryachev.memsafecrypto.salsa.XSalsa20Decryptor in = new goryachev.memsafecrypto.salsa.XSalsa20Decryptor(key, nonce, encrypted);
			CByteArray decrypted = new CByteArray(size); 
			in.decrypt(decrypted);
			in.zero();
			
			TF.eq(decrypted.toByteArray(), data.toByteArray());
		}
	}
}
