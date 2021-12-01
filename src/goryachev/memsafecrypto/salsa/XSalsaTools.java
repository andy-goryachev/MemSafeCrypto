// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * XSalsa20poly1306 Tools.
 */
public class XSalsaTools
{
	public static final int KEY_LENGTH_BYTES = 256 / 8;
	public static final int NONCE_LENGTH_BYTES = 192 / 8;
	public static final int MAC_LENGTH_BYTES = 128 / 8;
	public static final int BUFFER_SIZE = 4096;
	
	
	public static CByteArray decrypt(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, byte[] ciphertext, int offset, int length)
	{
		XSalsa20Engine eng = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				eng.init(false, new ParametersWithIV(kp, nonce, nonceOffset, nonceLength));
		
				CByteArray dec = new CByteArray(length);
				eng.processBytes(ciphertext, offset, length, dec, 0);
				return dec;
			}
			finally
			{
				kp.zero();
			}
		}
		finally
		{
			eng.zero();
		}
	}
	
	
	public static void encrypt(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, CByteArray cleartext, byte[] out, int outOffset)
	{
		XSalsa20Engine eng = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				eng.init(true, new ParametersWithIV(kp, nonce, nonceOffset, nonceLength));
				
				eng.processBytes(cleartext, 0, cleartext.length(), out, outOffset);
			}
			finally
			{
				kp.zero();
			}
		}
		finally
		{
			eng.zero();
		}
	}
}
