// Copyright © 2020-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.common.util.D;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CRandom;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.Arrays;


/**
 * Tests XSalsaRandomAccessFile.
 */
public class TestXSalsaRandomAccessFile
{
	public static void main(String[] arg)
	{
		TF.run();
	}
	
	
	@Test
	public void test() throws Exception
	{
		int iterations = 10_000;
		int chunkSize = 10_000;
		int fileSize = 20_000_000;
		
		File decFile = tempFile("dec.dat");
		File encFile = tempFile("enc.dat");
		
		CRandom r = new CRandom();
		
		byte[] buf = new byte[fileSize];
		r.nextBytes(buf);
		
		CKit.write(buf, decFile);

		CByteArray key = new CByteArray(256/8);
		r.nextBytes(key);
		
		CByteArray iv = new CByteArray(192/8);
		r.nextBytes(iv);
		
		XSalsaRandomAccessFile sf = new XSalsaRandomAccessFile(encFile, true, key, iv);
		try
		{
			sf.write(buf);
		}
		finally
		{
			CKit.close(sf);
		}
		
		for(int i=0; i<iterations; i++)
		{
			int len = r.nextInt(chunkSize);
			int off = r.nextInt(fileSize - len);
			
			t(decFile, encFile, off, len, key, iv);
		}
	}


	protected void t(File decFile, File encFile, int off, int len, CByteArray key, CByteArray iv) throws Exception
	{
		byte[] bufDec = new byte[len];
		byte[] bufEnc = new byte[len];

		RandomAccessFile raf = new RandomAccessFile(decFile, "r");
		try
		{
			raf.seek(off);
			raf.readFully(bufDec);
			
			XSalsaRandomAccessFile sf = new XSalsaRandomAccessFile(encFile, false, key, iv);
			try
			{
				// make sure it does read
				Arrays.fill(bufEnc, (byte)0x55);
				
				sf.seek(off);
				sf.readFully(bufEnc);
			}
			finally
			{
				CKit.close(sf);
			}
		}
		finally
		{
			CKit.close(raf);
		}
		
		TF.eq(bufDec, bufDec);
	}
	
	
	@Test
	public void testRAF() throws Exception
	{
		File f = File.createTempFile("DirCrypt_TestFileIO", null);
		f.deleteOnExit();
		D.print(f);
		
		CByteArray key = genBytes(XSalsaTools.KEY_LENGTH_BYTES);
		CByteArray iv = genBytes(XSalsaTools.NONCE_LENGTH_BYTES);
		XSalsaRandomAccessFile xf = new XSalsaRandomAccessFile(f, true, key, iv);
		try
		{
			byte[] clear =
			{
				0x01, 0x02, (byte)0xaa, 0x55
			};
			xf.writeUnencrypted(clear);
			
			byte[] enc = new byte[4];
			xf.write(enc);

			byte[] dec = new byte[enc.length];
			xf.seek(4L);
			xf.readFully(dec);
			TF.eq(dec, enc);
			
			byte[] clr = new byte[clear.length];
			xf.seek(0L);
			xf.readUnencrypted(clr);
			TF.eq(clear, clr);
		}
		finally
		{
			CKit.close(xf);
		}
		
		D.print("len=", f.length());
		byte[] b = CKit.readBytes(f);
		
		D.dump(b);
	}


	private CByteArray genBytes(int sz)
	{
		byte[] b = new byte[sz];
		return CByteArray.readOnly(b);
	}
	
	
	private static File tempFile(String prefix) throws Exception
	{
		File f = File.createTempFile(prefix, null);
		f.deleteOnExit();
		return f;
	}
}
