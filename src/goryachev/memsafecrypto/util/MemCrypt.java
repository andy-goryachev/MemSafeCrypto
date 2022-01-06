// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.Blake2bDigest;
import goryachev.memsafecrypto.salsa.XSalsaTools;
import java.security.SecureRandom;


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
	private static final int staticEntropy1 = initStaticEntropy();
	private static final int staticEntropy2 = initStaticEntropy();
	private static final int staticEntropy3 = initStaticEntropy();
	private static final int staticEntropy4 = initStaticEntropy();

	
	public static final CByteArray encrypt(CByteArray data) throws Exception
	{
		int encryptedLength = data.length() + XSalsaTools.NONCE_LENGTH_BYTES;
		CByteArray out = new CByteArray(encryptedLength);

		CByteArray nonce = new CByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
		CUtils.nextBytes(new SecureRandom(), nonce);
		
		out.write(nonce);
		
		CByteArray key = generateKey();
		try
		{
			XSalsaTools.encryptXSalsa20(key, nonce, data, out, XSalsaTools.NONCE_LENGTH_BYTES, data.length());
		}
		finally
		{
			key.zero();
		}
		
		return out;
	}
	
	
	public static final CByteArray decrypt(CByteArray data) throws Exception
	{
		int decryptedLength = data.length() - XSalsaTools.NONCE_LENGTH_BYTES;
		
		CByteArray nonce = new CByteArray(XSalsaTools.NONCE_LENGTH_BYTES);
		nonce.copyFrom(data, 0, nonce.length(), 0);
		
		CByteArray out = new CByteArray(decryptedLength);
		
		CByteArray key = generateKey();
		try
		{
			XSalsaTools.decryptXSalsa20(key, nonce, XSalsaTools.NONCE_LENGTH_BYTES, decryptedLength, data, out);
		}
		finally
		{
			key.zero();
		}
		
		return out;
	}
	
	
	/** it is expected this key will not change for duration of the program */
	private static final CByteArray generateKey() throws Exception
	{
		Blake2bDigest d = new Blake2bDigest(XSalsaTools.KEY_LENGTH_BYTES * 8);
		
		d.update((byte)staticEntropy1);
		d.update((byte)staticEntropy2);
		d.update((byte)staticEntropy3);
		d.update((byte)staticEntropy4);
		update(d, Object.class.hashCode());
		update(d, String.class.hashCode());
		update(d, MemCrypt.class.hashCode());
		
		CByteArray b = new CByteArray(d.getDigestSize());
		d.doFinal(b, 0);
		b.setReadOnly();
		return b;
	}


	private static final void update(Blake2bDigest d, int x)
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
