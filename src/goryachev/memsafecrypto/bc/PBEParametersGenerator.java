package goryachev.memsafecrypto.bc;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;


/**
 * super class for all Password Based Encryption (PBE) parameter generator classes.
 */
public abstract class PBEParametersGenerator
{
	/**
	 * generate derived parameters for a key of length keySize.
	 *
	 * @param keySize the length, in bits, of the key required.
	 * @return a parameters object representing a key.
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize);

	/**
	 * generate derived parameters for a key of length keySize, and
	 * an initialisation vector (IV) of length ivSize.
	 *
	 * @param keySize the length, in bits, of the key required.
	 * @param ivSize the length, in bits, of the iv required.
	 * @return a parameters object representing a key and an IV.
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize, int ivSize);

	/**
	 * generate derived parameters for a key of length keySize, specifically
	 * for use with a MAC.
	 *
	 * @param keySize the length, in bits, of the key required.
	 * @return a parameters object representing a key.
	 */
	public abstract CipherParameters generateDerivedMacParameters(int keySize);

	//
	
	protected byte[] password;
	protected byte[] salt;
	protected int iterationCount;

	
	/**
	 * base constructor.
	 */
	protected PBEParametersGenerator()
	{
	}


	/**
	 * initialise the PBE generator.
	 *
	 * @param password the password converted into bytes (see below).
	 * @param salt the salt to be mixed with the password.
	 * @param iterationCount the number of iterations the "mixing" function
	 * is to be applied for.
	 */
	public void init(byte[] password, byte[] salt, int iterationCount)
	{
		this.password = password;
		this.salt = salt;
		this.iterationCount = iterationCount;
	}


	/**
	 * return the password byte array.
	 *
	 * @return the password byte array.
	 */
	public byte[] getPassword()
	{
		return password;
	}


	/**
	 * return the salt byte array.
	 *
	 * @return the salt byte array.
	 */
	public byte[] getSalt()
	{
		return salt;
	}


	/**
	 * return the iteration count.
	 *
	 * @return the iteration count.
	 */
	public int getIterationCount()
	{
		return iterationCount;
	}


	/**
	 * converts a password to a byte array according to the scheme in
	 * PKCS5 (ascii, no padding)
	 *
	 * @param password a character array representing the password.
	 * @return a byte array representing the password.
	 */
	public static byte[] PKCS5PasswordToBytes(char[] password)
	{
		if(password != null)
		{
			byte[] bytes = new byte[password.length];

			for(int i = 0; i != bytes.length; i++)
			{
				bytes[i] = (byte)password[i];
			}

			return bytes;
		}
		else
		{
			return new byte[0];
		}
	}


	/**
	 * converts a password to a byte array according to the scheme in
	 * PKCS5 (UTF-8, no padding)
	 *
	 * @param password a character array representing the password.
	 * @return a byte array representing the password.
	 */
	public static byte[] PKCS5PasswordToUTF8Bytes(char[] password)
	{
		if(password != null)
		{
			return toUTF8ByteArray(password);
		}
		else
		{
			return new byte[0];
		}
	}
	
	
	@Deprecated // FIX remove
    private static byte[] toUTF8ByteArray(char[] string)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            toUTF8ByteArray(string, bOut);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.toByteArray();
	}


	@Deprecated // FIX remove or move
	private static void toUTF8ByteArray(char[] string, OutputStream sOut) throws IOException
	{
		char[] c = string;
		int i = 0;

		while(i < c.length)
		{
			char ch = c[i];

			if(ch < 0x0080)
			{
				sOut.write(ch);
			}
			else if(ch < 0x0800)
			{
				sOut.write(0xc0 | (ch >> 6));
				sOut.write(0x80 | (ch & 0x3f));
			}
			// surrogate pair
			else if(ch >= 0xD800 && ch <= 0xDFFF)
			{
				// in error - can only happen, if the Java String class has a
				// bug.
				if(i + 1 >= c.length)
				{
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				char W1 = ch;
				ch = c[++i];
				char W2 = ch;
				// in error - can only happen, if the Java String class has a
				// bug.
				if(W1 > 0xDBFF)
				{
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
				sOut.write(0xf0 | (codePoint >> 18));
				sOut.write(0x80 | ((codePoint >> 12) & 0x3F));
				sOut.write(0x80 | ((codePoint >> 6) & 0x3F));
				sOut.write(0x80 | (codePoint & 0x3F));
			}
			else
			{
				sOut.write(0xe0 | (ch >> 12));
				sOut.write(0x80 | ((ch >> 6) & 0x3F));
				sOut.write(0x80 | (ch & 0x3F));
			}

			i++;
		}
	}


	/**
	 * converts a password to a byte array according to the scheme in
	 * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
	 *
	 * @param password a character array representing the password.
	 * @return a byte array representing the password.
	 */
	public static byte[] PKCS12PasswordToBytes(char[] password)
	{
		if(password != null && password.length > 0)
		{
			// +1 for extra 2 pad bytes.
			byte[] bytes = new byte[(password.length + 1) * 2];

			for(int i = 0; i != password.length; i++)
			{
				bytes[i * 2] = (byte)(password[i] >>> 8);
				bytes[i * 2 + 1] = (byte)password[i];
			}

			return bytes;
		}
		else
		{
			return new byte[0];
		}
	}
}
