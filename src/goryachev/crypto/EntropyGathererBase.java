// Copyright © 2012-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import goryachev.common.util.CKit;
import goryachev.common.util.WeakList;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;


/**
 * An entropy gathering component and corresponding SecureRandom.
 * <p>
 * This goal of this implementation is to improve security of the standard JVM 
 * implementation by using a publicly known algorithm (Bouncycastle's DigestRandomGenerator),
 * while using both JVM SecureRandom and user AWT events as the source of entropy.
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
	
	protected final DigestRandomGenerator random;
	private final SecureRandomSpi spi;
	private final Provider provider;
	protected final SecureRandom jvmRandom;
	private static WeakList<Listener> listeners;
	
	
	protected EntropyGathererBase(String name)
	{
		jvmRandom = new SecureRandom();

		random = new DigestRandomGenerator(new SHA512Digest());
		
		spi = new SecureRandomSpi()
		{
			private boolean init = true;
			
			protected final void engineSetSeed(byte[] seed)
			{
				random.addSeedMaterial(seed);
			}

			protected final void engineNextBytes(byte[] bytes)
			{
				if(init)
				{
					// initialize generator with randomness from jvm
					random.addSeedMaterial(jvmRandom.generateSeed(256));
					init = false;
				}
				else
				{
					random.addSeedMaterial(jvmRandom.nextLong());					
				}
				
				random.addSeedMaterial(System.currentTimeMillis());
				random.addSeedMaterial(Runtime.getRuntime().freeMemory());
				random.addSeedMaterial(System.nanoTime());
				
				random.nextBytes(bytes);
			}

			protected final byte[] engineGenerateSeed(int numBytes)
			{
				byte[] b = new byte[numBytes];
				engineNextBytes(b);
				return b;
			}
		};
		
		provider = new Provider(name, 1.2, "andy goryachev") { };
	}
	
	
	public static final void addListener(Listener li)
	{
		if(listeners == null)
		{
			listeners = new WeakList();
		}
		
		listeners.add(li);
	}
	
	
	protected static final void tick()
	{
		if(listeners != null)
		{
			for(Listener li: listeners.asList())
			{
				li.onEntropyCollectionTick();
			}
			
			if(listeners.size() == 0)
			{
				listeners = null;
			}
		}
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(long x)
	{
		random.addSeedMaterial(x);
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(byte[] x)
	{
		random.addSeedMaterial(x);
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(double x)
	{
		random.addSeedMaterial(Double.doubleToLongBits(x));
	}
	
	
	/** Adds entropy to the generator. */
	public final void addSeedMaterial(String s)
	{
		byte[] b = s.getBytes(CKit.CHARSET_UTF8);
		random.addSeedMaterial(b);
	}
	
	
	public final SecureRandom getSecureRandomGenerator()
	{
		return new SecureRandom(spi, provider) { };
	}
}
