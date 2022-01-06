// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.log.Log;
import java.util.Arrays;


/**
 * Crypto Tools.
 */
public final class Crypto
{
	protected static final Log log = Log.get("Crypto");
	
	
	public static void zero(ICryptoZeroable z)
	{
		if(z != null)
		{
			try
			{
				z.zero();
			}
			catch(Throwable e)
			{
				log.error(e);
			}
		}
	}
	
	
	public static final void zero(byte[] b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b, (byte)0);
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static final void zero(char[] b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b, '\u0000');
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
}
