// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.io.InputStream;
import java.security.SecureRandom;


/**
 * Crypto Tools.
 */
public class CryptoTools
{
	public static void readFully(InputStream in, CByteArray out) throws Exception
	{
		int sz = out.length();
		for(int i=0; i<sz; i++)
		{
			int c = in.read();
			if(c < 0)
			{
				throw new Exception("EOF");
			}
			
			out.write(c);
		}
	}
	

	public static void nextBytes(SecureRandom rnd, CByteArray buf)
	{
		// if we leak one byte at a time, would that be ok?
		byte[] b = new byte[1];
		int sz = buf.length();
		
		for(int i=0; i<sz; i++)
		{
			rnd.nextBytes(b);
			buf.write(b);
		}
	}


	public static void arraycopy(CByteArray src, int srcPos, byte[] dst, int dstPos, int len)
	{
		for(int i=0; i<len; i++)
		{
			byte b = src.get(srcPos + i);
			dst[dstPos + i] = b;
		}
	}
}
