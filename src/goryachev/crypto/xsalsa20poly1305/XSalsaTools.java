// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.xsalsa20poly1305;
import goryachev.crypto.Crypto;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * XSalsa20poly1306 Tools.
 */
public class XSalsaTools
{
	public static final int KEY_LENGTH_BYTES = 256 / 8;
	public static final int NONCE_LENGTH_BYTES = 192 / 8;
	public static final int MAC_LENGTH_BYTES = 128 / 8;
	public static final int BUFFER_SIZE = 4096;
	
	
	/** clears the engine internals by initializing it with an all-zero key and nonce */
	public static void zero(XSalsa20Engine x)
	{
		byte[] k = new byte[KEY_LENGTH_BYTES];
		byte[] nonce = new byte[NONCE_LENGTH_BYTES];
		x.init(false, new ParametersWithIV(new KeyParameter(k), nonce));
	}


	/** clears the digest by initializing it with an all-zero key */
	public static void zero(Poly1305 x)
	{
		byte[] k = new byte[NONCE_LENGTH_BYTES];
		x.init(new KeyParameter(k));
	}
	
	
	public static byte[] decrypt(byte[] key, byte[] nonce, int nonceOffset, int nonceLength, byte[] ciphertext, int offset, int length)
	{
		XSalsa20Engine eng = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				eng.init(false, new ParametersWithIV(kp, nonce, nonceOffset, nonceLength));
		
				byte[] dec = new byte[length];
				eng.processBytes(ciphertext, offset, length, dec, 0);
				return dec;
			}
			finally
			{
				Crypto.zero(kp);
			}
		}
		finally
		{
			zero(eng);
		}
	}
	
	
	public static void encrypt(byte[] key, byte[] nonce, int nonceOffset, int nonceLength, byte[] cleartext, byte[] out, int outOffset)
	{
		XSalsa20Engine eng = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				eng.init(true, new ParametersWithIV(kp, nonce, nonceOffset, nonceLength));
		
				eng.processBytes(cleartext, 0, cleartext.length, out, outOffset);
			}
			finally
			{
				Crypto.zero(kp);
			}
		}
		finally
		{
			zero(eng);
		}
	}
}
