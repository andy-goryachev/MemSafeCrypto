// Copyright © 2020-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CRandom;
import goryachev.memsafecrypto.salsa.XSalsaRandomAccessFile;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.Arrays;


/**
 * Tests XSalsaRandomAccessFile.
 */
public class TestXSalsaRandomAccessFile
{
	private static final File DIR = new File("H:/Test/AccessPanel/TestXSalsaRandomAccessFile");
	
	
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
		
		File decFile = new File(DIR, "dec.dat");
		File encFile = new File(DIR, "enc.dat");
		
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
}
