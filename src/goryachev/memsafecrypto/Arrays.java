package goryachev.memsafecrypto;


/**
 * General array utilities.
 */
public final class Arrays
{
	public static void fill(byte[] a, byte val)
	{
		java.util.Arrays.fill(a, val);
	}


	public static void fill(long[] a, long val)
	{
		java.util.Arrays.fill(a, val);
	}

	
	public static byte[] clone(byte[] data)
	{
		return null == data ? null : data.clone();
	}


	public static long[] clone(long[] data)
	{
		return null == data ? null : data.clone();
	}
}
