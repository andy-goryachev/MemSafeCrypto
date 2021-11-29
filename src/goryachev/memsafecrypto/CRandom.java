// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.security.SecureRandom;


/**
 * Secure Random Number Generator based on CRandomSpi 
 * (digest random generator + stock jvm secure random)
 * with additional method for generating random bytes into CByteArray.
 */
public class CRandom
	extends SecureRandom
{
	public CRandom()
	{
		super(CRandomSpi.getInstance(), CRandomSpi.getInstance().getProvider());
	}
	

	public void nextBytes(CByteArray bytes)
	{
		CRandomSpi.getInstance().engineNextBytes(bytes);
	}


	public String getAlgorithm()
	{
		return "andy@goryachev/Blake2b512+jvm";
	}
}
