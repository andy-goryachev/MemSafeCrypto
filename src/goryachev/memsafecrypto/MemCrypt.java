// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import goryachev.memsafecrypto.bc.Blake2bDigest;
import goryachev.memsafecrypto.bc.salsa.XSalsa20DecryptStream;
import goryachev.memsafecrypto.bc.salsa.XSalsa20EncryptStream;
import goryachev.memsafecrypto.bc.salsa.XSalsaTools;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

	
//	public static final byte[] encrypt(ByteArray data) throws Exception
//	{
//		int encryptedLength = data.length() + XSalsaTools.NONCE_LENGTH_BYTES;
//		ByteArrayOutputStream out = new ByteArrayOutputStream(encryptedLength);
//
//		byte[] nonce = new byte[XSalsaTools.NONCE_LENGTH_BYTES];
//		new SecureRandom().nextBytes(nonce);
//		
//		out.write(nonce);
//		
//		// TODO ByteArray
//		byte[] key = generateKey();
//		try
//		{
//			XSalsa20EncryptStream os = new XSalsa20EncryptStream(key, nonce, out);
//			os.write(data);
//			os.close();
//		}
//		finally
//		{
//			Crypto.zero(key);
//		}
//		
//		return out.toByteArray();
//	}
	
	
	public static final byte[] encrypt(byte[] data) throws Exception
	{
		int encryptedLength = data.length + XSalsaTools.NONCE_LENGTH_BYTES;
		ByteArrayOutputStream out = new ByteArrayOutputStream(encryptedLength);

		byte[] nonce = new byte[XSalsaTools.NONCE_LENGTH_BYTES];
		new SecureRandom().nextBytes(nonce);
		
		out.write(nonce);
		
		// TODO ByteArray
		byte[] key = generateKey();
		try
		{
			XSalsa20EncryptStream os = new XSalsa20EncryptStream(key, nonce, out);
			os.write(data);
			os.close();
		}
		finally
		{
			Crypto.zero(key);
		}
		
		return out.toByteArray();
	}
	

	public static final byte[] decrypt(byte[] data) throws Exception
	{
		int decryptedLength = data.length - XSalsaTools.NONCE_LENGTH_BYTES;
		
		ByteArrayInputStream in = new ByteArrayInputStream(data);

		byte[] nonce = new byte[XSalsaTools.NONCE_LENGTH_BYTES];
		CKit.readFully(in, nonce);
		
		byte[] out = new byte[decryptedLength];
		
		// TODO ByteArray
		byte[] key = generateKey();
		try
		{
			XSalsa20DecryptStream is = new XSalsa20DecryptStream(key, nonce, data.length, in);
			CKit.readFully(is, out);
			is.close();
		}
		finally
		{
			Crypto.zero(key);
		}
		
		// TODO ByteArray
		return out;
	}
	
	
	/** it is expected this key will not change for duration of the program */
	private static final byte[] generateKey() throws Exception
	{
		Blake2bDigest d = new Blake2bDigest(XSalsaTools.KEY_LENGTH_BYTES * 8);
		
		d.update((byte)staticEntropy1);
		d.update((byte)staticEntropy2);
		d.update((byte)staticEntropy3);
		d.update((byte)staticEntropy4);
		update(d, Object.class.hashCode());
		update(d, String.class.hashCode());
		update(d, MemCrypt.class.hashCode());
		
		// TODO byte array
		byte[] b = new byte[d.getDigestSize()];
		d.doFinal(b, 0);
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
