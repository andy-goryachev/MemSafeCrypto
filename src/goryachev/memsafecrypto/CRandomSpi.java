// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.bc.Blake2bDigest;
import goryachev.memsafecrypto.bc.DigestRandomGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;


/**
 * CRandom Service Provider Implementation.
 */
public final class CRandomSpi
	extends SecureRandomSpi
{
	private final DigestRandomGenerator generator;
	private final Provider provider;
	private static CRandomSpi instance;


	public CRandomSpi()
	{
		provider = new Provider("andy@goryachev.com", 1.3, "andy@goryachev.com") { };
		
		generator = new DigestRandomGenerator(new Blake2bDigest(512));
		
		// add initial entropy from the jvm and other sources
		SecureRandom r = new SecureRandom();
		generator.addSeedMaterial(r.generateSeed(256));
		generator.addSeedMaterial(System.currentTimeMillis());
		generator.addSeedMaterial(Runtime.getRuntime().freeMemory());
		generator.addSeedMaterial(System.nanoTime());
	}
	
	
	public static final CRandomSpi getInstance()
	{
		if(instance == null)
		{
			synchronized(CRandomSpi.class)
			{
				if(instance == null)
				{
					instance = new CRandomSpi();
				}
			}
		}
		return instance;
	}
	
	
	public final Provider getProvider()
	{
		return provider;
	}
	

	protected final void engineSetSeed(byte[] seed)
	{
		generator.addSeedMaterial(seed);
	}
	

	protected final void engineNextBytes(byte[] bytes)
	{
		generator.nextBytes(bytes);
	}
	
	
	protected final void engineNextBytes(CByteArray bytes)
	{
		generator.nextBytes(bytes);
	}
	

	protected final byte[] engineGenerateSeed(int byteCount)
	{
		byte[] b = new byte[byteCount];
		engineNextBytes(b);
		return b;
	}
	
	
	public void addSeedMaterial(long x)
	{
		generator.addSeedMaterial(x);
	}
	
	
	public void addSeedMaterial(byte[] x)
	{
		generator.addSeedMaterial(x);
	}
}
