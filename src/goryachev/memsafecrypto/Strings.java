package goryachev.memsafecrypto;


/**
 * String utilities.
 */
public final class Strings
{
	public static byte[] toByteArray(String string)
	{
		byte[] bytes = new byte[string.length()];

		for(int i = 0; i != bytes.length; i++)
		{
			char ch = string.charAt(i);

			bytes[i] = (byte)ch;
		}

		return bytes;
	}
}
