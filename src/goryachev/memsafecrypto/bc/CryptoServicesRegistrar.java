package goryachev.memsafecrypto.bc;
import java.security.SecureRandom;


/**
 * Basic registrar class for providing defaults for cryptography services in this module.
 */
public final class CryptoServicesRegistrar
{
	private static final Object cacheLock = new Object();
	private static SecureRandom defaultSecureRandom;


	private CryptoServicesRegistrar()
	{
	}


	/**
	 * Return the default source of randomness.
	 *
	 * @return the default SecureRandom
	 */
	public static SecureRandom getSecureRandom()
	{
		synchronized(cacheLock)
		{
			if(null != defaultSecureRandom)
			{
				return defaultSecureRandom;
			}
		}

		SecureRandom tmp = new SecureRandom();

		synchronized(cacheLock)
		{
			if(null == defaultSecureRandom)
			{
				defaultSecureRandom = tmp;
			}

			return defaultSecureRandom;
		}
	}


	/**
	 * Return either the passed-in SecureRandom, or if it is null, then the default source of randomness.
	 *
	 * @param secureRandom the SecureRandom to use if it is not null.
	 * @return the SecureRandom parameter if it is not null, or else the default SecureRandom
	 */
	public static SecureRandom getSecureRandom(SecureRandom secureRandom)
	{
		return null == secureRandom ? getSecureRandom() : secureRandom;
	}


	/**
	 * Set a default secure random to be used where none is otherwise provided.
	 *
	 * @param secureRandom the SecureRandom to use as the default.
	 */
	public static void setSecureRandom(SecureRandom secureRandom)
	{
		// TODO this library does not check permissions due to AccessManager deprecation
		//checkPermission(CanSetDefaultRandom);

		synchronized(cacheLock)
		{
			defaultSecureRandom = secureRandom;
		}
	}
}
