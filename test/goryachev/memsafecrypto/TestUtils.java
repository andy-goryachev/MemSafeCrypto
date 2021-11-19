// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;


/**
 * Test Utilities.
 */
public class TestUtils
{
	public static byte[] rnd(int size)
	{
		byte[] b = new byte[size];
		new Random().nextBytes(b);
		return b;
	}
	
	
	public static CByteArray rndByteArray(int size)
	{
		byte[] b = new byte[size];
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
