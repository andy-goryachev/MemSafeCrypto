// Copyright © 2012-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.bc.Blake2bDigest;
import goryachev.memsafecrypto.bc.DigestRandomGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;


/**
 * An entropy gathering component and corresponding SecureRandom.
 * <p>
 * This goal of this implementation is to "improve" security of the standard JVM 
 * implementation by using a publicly known algorithm (Bouncycastle's DigestRandomGenerator),
 * while using both JVM SecureRandom and user-generated events as the source of entropy.
 * <p>
 * By using both sources the overall quality of the generated random numbers should improve,
 * even assuming a possibility that the JVM implementation is compromised, as in this case:
 * http://www.theregister.co.uk/2013/08/12/android_bug_batters_bitcoin_wallets/
 */
public abstract class EntropyGathererBase
{
	public static interface Listener
	{
		public void onEntropyCollectionTick();
	}
	
	//
	
	protected final DigestRandomGenerator generator;
	private final SecureRandomSpi spi;
	private final Provider provider;
	protected final SecureRandom jvmRandom;
	
	
	protected EntropyGathererBase(String name)
	{
		jvmRandom = new SecureRandom();

		generator = new DigestRandomGenerator(new Blake2bDigest(256));
		
		spi = new SecureRandomSpi()
		{
			private boolean init = true;
			
			
			protected final void engineSetSeed(byte[] seed)
			{
				generator.addSeedMaterial(seed);
			}
			

			protected final void engineNextBytes(byte[] bytes)
			{
				if(init)
				{
					// initialize generator with randomness from jvm
					generator.addSeedMaterial(jvmRandom.generateSeed(256));
					init = false;
				}
				else
				{
					generator.addSeedMaterial(jvmRandom.nextLong());					
				}
				
				generator.addSeedMaterial(System.currentTimeMillis());
				generator.addSeedMaterial(Runtime.getRuntime().freeMemory());
				generator.addSeedMaterial(System.nanoTime());
				
				generator.nextBytes(bytes);
			}
			

			protected final byte[] engineGenerateSeed(int numBytes)
			{
				byte[] b = new byte[numBytes];
				engineNextBytes(b);
				return b;
			}
		};
		
		provider = new Provider(name, 1.3, "andy@goryachev.com") { };
	}
	

	/** Adds entropy to the generator. */
	public final void addSeedMaterial(long x)
	{
		generator.addSeedMaterial(x);
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(byte[] x)
	{
		generator.addSeedMaterial(x);
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(double x)
	{
		generator.addSeedMaterial(Double.doubleToLongBits(x));
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(String s)
	{
		byte[] b = s.getBytes(CKit.CHARSET_UTF8);
		generator.addSeedMaterial(b);
	}
	
	
	public final SecureRandom getSecureRandomGenerator()
	{
		return new SecureRandom(spi, provider) { };
	}
}
