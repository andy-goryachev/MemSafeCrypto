// Copyright © 2010-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.common.util;
import goryachev.common.log.Log;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public final class CRandom
{
	protected static final Log log = Log.get("CRandom");
	public static final String RAND_ALGORITHM = "SHA1PRNG";
	private static SecureRandom random = init();
    
	
	private static SecureRandom init()
	{
		try
		{
			return SecureRandom.getInstance(RAND_ALGORITHM);
		}
		catch(NoSuchAlgorithmException e)
		{
			// should not happen
			log.error(e);
			throw new Error(e);
		}
	}
	
	
	public static byte[] generateBits(int bits)
	{
		byte[] b = new byte[bits >>> 3];
		synchronized(random)
		{
			random.nextBytes(b);
		}
		return b;
	}
	
	
	public static String generateHexBits(int bits)
	{
		byte[] b = generateBits(bits);
		return Hex.toHexString(b);
	}
	
	
	public static long nextLong()
	{
		synchronized(random)
		{
			return random.nextLong();
		}
	}
}
