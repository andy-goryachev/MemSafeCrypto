// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.util.CKit;
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
	
	
	public static void addSeedMaterial(long x)
	{
		CRandomSpi.getInstance().addSeedMaterial(x);
	}
	
	
	public static void addSeedMaterial(double x)
	{
		long v = Double.doubleToLongBits(x);
		CRandomSpi.getInstance().addSeedMaterial(v);
	}
	
	
	public static void addSeedMaterial(String x)
	{
		byte[] b = x.getBytes(CKit.CHARSET_UTF8);
		CRandomSpi.getInstance().addSeedMaterial(b);
	}
}
