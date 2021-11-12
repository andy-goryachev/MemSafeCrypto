// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;


/**
 * Utility methods.
 */
public class Utils
{
	public static byte[] clone(byte[] data)
	{
		return null == data ? null : data.clone();
	}


	public static long[] clone(long[] data)
	{
		return null == data ? null : data.clone();
	}
}
