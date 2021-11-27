package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CCharArray;
import goryachev.memsafecrypto.util.CUtils;


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
	
	protected CByteArray password;
	protected CByteArray salt;
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
	 * 
	 * This method create a copy of password and salt.  The caller should manage
	 * zeroing of the arguments passed here.
	 */
	public void init(CByteArray password, CByteArray salt, int iterationCount)
	{
		this.password = CByteArray.readOnly(password);
		this.salt = CByteArray.readOnly(salt);
		this.iterationCount = iterationCount;
	}


	/**
	 * return the password byte array.
	 *
	 * @return the password byte array.
	 */
	public CByteArray getPassword()
	{
		return password;
	}


	/**
	 * return the salt byte array.
	 *
	 * @return the salt byte array.
	 */
	public CByteArray getSalt()
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
	public static CByteArray PKCS5PasswordToBytes(CCharArray password)
	{
		if(password != null)
		{
			CByteArray bytes = new CByteArray(password.length());

			for(int i=0; i<bytes.length(); i++)
			{
				bytes.set(i, (byte)password.get(i));
			}

			return bytes;
		}
		else
		{
			return new CByteArray(0);
		}
	}


	/**
	 * converts a password to a byte array according to the scheme in
	 * PKCS5 (UTF-8, no padding)
	 *
	 * @param password a character array representing the password.
	 * @return a byte array representing the password.
	 */
	public static CByteArray PKCS5PasswordToUTF8Bytes(CCharArray password)
	{
		if(password != null)
		{
			return CUtils.toUTF8ByteArray(password);
		}
		else
		{
			return new CByteArray(0);
		}
	}
	

	/**
	 * converts a password to a byte array according to the scheme in
	 * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
	 *
	 * @param password a character array representing the password.
	 * @return a byte array representing the password.
	 */
	public static CByteArray PKCS12PasswordToBytes(CCharArray password)
	{
		if(password != null && password.length() > 0)
		{
			// +1 for extra 2 pad bytes.
			CByteArray bytes = new CByteArray((password.length() + 1) * 2);

			for(int i=0; i<password.length(); i++)
			{
				bytes.set(i * 2, (byte)(password.get(i) >>> 8));
				bytes.set(i * 2 + 1, (byte)password.get(i));
			}

			return bytes;
		}
		else
		{
			return new CByteArray(0);
		}
	}
}
