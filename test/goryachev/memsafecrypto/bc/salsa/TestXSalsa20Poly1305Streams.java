// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.common.util.D;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.TUtils;
import goryachev.memsafecrypto.salsa.XSalsaTools;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;


/**
 * Tests XSalsa20Poly1305 Streams.
 */
public class TestXSalsa20Poly1305Streams
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	/*
	total bytes: 100,000,000
	BC encryption: 1.21
	MemSafe encryption: 1.49
	*/
	@Test
	public void testEncryptionSpeed() throws Exception
	{
		// BC seems to have a cold start delay, measure on second pass
		tspeed(false);
		tspeed(true);
	}
	
	
	protected void tspeed(boolean showResult) throws Exception
	{
		int count = 10;
		int size = 10_000_000;
		
		long timeBC = 0;
		long timeMemSafe = 0;
		
		for(int i=0; i<count; i++)
		{
			byte[] key = TUtils.rnd(XSalsaTools.KEY_LENGTH_BYTES);
			byte[] nonce = TUtils.rnd(XSalsaTools.NONCE_LENGTH_BYTES);
			byte[] data = TUtils.rnd(size);
			
			long start = System.nanoTime();
			OutputStream os1 = TUtils.nullOutputStream();
			goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305EncryptStream out1 = new goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305EncryptStream(key, nonce, os1);
			out1.write(data);
			out1.close();
			timeBC += (System.nanoTime() - start);
			
			start = System.nanoTime();
			OutputStream os2 = TUtils.nullOutputStream();
			goryachev.memsafecrypto.salsa.XSalsa20Poly1305EncryptStream out2 = new goryachev.memsafecrypto.salsa.XSalsa20Poly1305EncryptStream(CByteArray.readOnly(key), CByteArray.readOnly(nonce), os2);
			out2.write(data);
			out2.close();
			timeMemSafe += (System.nanoTime() - start);
		}
		
		if(showResult)
		{
			String res = 
				"\n" +
				String.format("total bytes: %,d", (size * count)) + "\n" +
				String.format("BC encryption: %.2f", timeBC / 1_000_000_000.0) + "\n" +
				String.format("MemSafe encryption: %.2f", timeMemSafe / 1_000_000_000.0);
			
			D.print(res);
		}
	}
	
	
	@Test
	public void testEncrypt() throws Exception
	{
		int count = 500;
		int size = 65537;
		
		for(int i=0; i<count; i++)
		{
			byte[] key = TUtils.rnd(XSalsaTools.KEY_LENGTH_BYTES);
			byte[] nonce = TUtils.rnd(XSalsaTools.NONCE_LENGTH_BYTES);
			byte[] data = TUtils.rnd(size);
			
			ByteArrayOutputStream os1 = new ByteArrayOutputStream(size);
			goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305EncryptStream out1 = new goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305EncryptStream(key, nonce, os1);
			out1.write(data);
			out1.close();
			byte[] b1 = os1.toByteArray();
			
			ByteArrayOutputStream os2 = new ByteArrayOutputStream(size);
			goryachev.memsafecrypto.salsa.XSalsa20Poly1305EncryptStream out2 = new goryachev.memsafecrypto.salsa.XSalsa20Poly1305EncryptStream(CByteArray.readOnly(key), CByteArray.readOnly(nonce), os2);
			out2.write(data);
			out2.close();
			byte[] b2 = os2.toByteArray();
			
			TF.eq(b1, b2);
			
			ByteArrayInputStream is1 = new ByteArrayInputStream(b1);
			goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305DecryptStream in1 = new goryachev.crypto.xsalsa20poly1305.XSalsa20Poly1305DecryptStream(key, nonce, b1.length, is1);
			byte[] cb1 = new byte[size]; 
			CKit.readFully(in1, cb1);
			in1.close();
			
			ByteArrayInputStream is2 = new ByteArrayInputStream(b1);
			goryachev.memsafecrypto.salsa.XSalsa20Poly1305DecryptStream in2 = new goryachev.memsafecrypto.salsa.XSalsa20Poly1305DecryptStream(CByteArray.readOnly(key), CByteArray.readOnly(nonce), b2.length, is2);
			byte[] cb2 = new byte[size]; 
			CKit.readFully(in2, cb2);
			in2.close();
			
			TF.eq(cb1, cb2);
			TF.eq(cb1, data);
		}
	}
}
