// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
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
	
	
	@Deprecated // caller should use CByteArray instead
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
}
