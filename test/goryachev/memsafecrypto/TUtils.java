// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;


/**
 * Test Utilities.
 */
public class TUtils
{
	public static byte[] rnd(int sizeInBytes)
	{
		byte[] b = new byte[sizeInBytes];
		new Random().nextBytes(b);
		return b;
	}
	
	
	public static CByteArray rndByteArray(int sizeInBytes)
	{
		byte[] b = new byte[sizeInBytes];
		new Random().nextBytes(b);
		return CByteArray.readOnly(b);
	}
	
	
	public static OutputStream nullOutputStream()
	{
		return new OutputStream()
		{
			public void write(int b) throws IOException
			{
			}
			
			
			public void write(byte[] b, int off, int len) throws IOException
			{
			}
		};
	}
}
