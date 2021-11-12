// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;


/** 
 * The goal of this mechanism is to encrypt sensitive data sitting in memory.
 * Used for Secret* and Opaque* classes.
 * 
 * The values are encrypted with a key generated each time from several jvm session parameters
 * such as Object.hashCode(), and a bit of (static) random data.  The key is not expected
 * to change within the same jvm session, but might differ between sessions. 
 */ 
public final class MemCrypt
{
	private static final int NONCE_SIZE_BYTES = 8;
	private static final int MAC_SIZE_BITS = 64;
	private static final byte[] ZERO_BYTE_ARRAY = new byte[0];
	private static final int staticEntropy1 = initStaticEntropy();
	private static final int staticEntropy2 = initStaticEntropy();
	private static final int staticEntropy3 = initStaticEntropy();
	private static final int staticEntropy4 = initStaticEntropy();

	
	public static final byte[] encrypt(byte[] data) throws Exception
	{
		EAXBlockCipher cipher = new EAXBlockCipher(new AESEngine());
		
		byte[] nonce = new byte[NONCE_SIZE_BYTES];
		new SecureRandom().nextBytes(nonce);

		byte[] key = generateKey();
		KeyParameter kp = new KeyParameter(key);
		try
		{
			AEADParameters par = new AEADParameters(kp, MAC_SIZE_BITS, nonce, ZERO_BYTE_ARRAY);
			cipher.init(true, par);
			
			int sz = cipher.getOutputSize(data.length);
			byte[] out = new byte[NONCE_SIZE_BYTES + sz];
			System.arraycopy(nonce, 0, out, 0, NONCE_SIZE_BYTES);

			int off = NONCE_SIZE_BYTES;
			off += cipher.processBytes(data, 0, data.length, out, off);
			cipher.doFinal(out, off);
			return out;
		}
		finally
		{
			Crypto.zero(kp);
			Crypto.zero(key);
		}
	}
	

	public static final byte[] decrypt(byte[] data) throws Exception
	{
		EAXBlockCipher cipher = new EAXBlockCipher(new AESEngine());
		
		byte[] nonce = new byte[NONCE_SIZE_BYTES];
		System.arraycopy(data, 0, nonce, 0, NONCE_SIZE_BYTES);
		
		byte[] key = generateKey();
		KeyParameter kp = new KeyParameter(key);
		try
		{
			AEADParameters par = new AEADParameters(kp, MAC_SIZE_BITS, nonce, ZERO_BYTE_ARRAY);
			cipher.init(false, par);
			
			int sz = cipher.getOutputSize(data.length - NONCE_SIZE_BYTES);
			byte[] out = new byte[sz];
			
			int off = cipher.processBytes(data, NONCE_SIZE_BYTES, data.length - NONCE_SIZE_BYTES, out, 0);
			cipher.doFinal(out, off);
			return out;
		}
		finally
		{
			Crypto.zero(kp);
			Crypto.zero(key);
		}
	}
	
	
	/** it is expected this key will not change for duration of the program */
	private static final byte[] generateKey() throws Exception
	{
		SHA256Digest d = new SHA256Digest();
		d.update((byte)staticEntropy1);
		d.update((byte)staticEntropy2);
		d.update((byte)staticEntropy3);
		d.update((byte)staticEntropy4);
		update(d, Object.class.hashCode());
		update(d, String.class.hashCode());
		update(d, MemCrypt.class.hashCode());
		byte[] b = new byte[d.getDigestSize()];
		d.doFinal(b, 0);
		return b;
	}


	private static final void update(Digest d, int x)
	{
		d.update((byte)(x >>> 24));
		d.update((byte)(x >>> 16));
		d.update((byte)(x >>>  8));
		d.update((byte)(x       ));
	}
	
	
	/** 
	 * let's add a bit of randomness without showing a high entropy object sitting in memory
	 * yes, I know, it's silly. 
	 */
	private static final int initStaticEntropy()
	{
		return new SecureRandom().nextInt() & 0xff;
	}
}
