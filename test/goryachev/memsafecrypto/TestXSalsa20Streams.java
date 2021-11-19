// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.bc.salsa.XSalsaTools;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;


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
		int size = 1_000_000;
		
		for(int i=0; i<count; i++)
		{
			CByteArray key = TestUtils.rndByteArray(XSalsaTools.KEY_LENGTH_BYTES);
			CByteArray nonce = TestUtils.rndByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
			CByteArray data = TestUtils.rndByteArray(size);
			
			CByteArray os = new CByteArray(size);
			goryachev.memsafecrypto.bc.salsa.XSalsa20EncryptStream out = new goryachev.memsafecrypto.bc.salsa.XSalsa20EncryptStream(key, nonce, os);
			out.write(data);
			out.close();
			byte[] encrypted = os.toByteArray();
			
			ByteArrayInputStream is = new ByteArrayInputStream(encrypted);
			goryachev.memsafecrypto.bc.salsa.XSalsa20DecryptStream in = new goryachev.memsafecrypto.bc.salsa.XSalsa20DecryptStream(key, nonce, encrypted.length, is);
			byte[] decrypted = new byte[size]; 
			CKit.readFully(in, decrypted);
			in.close();
			
			TF.eq(decrypted, data);
		}
	}
}
