// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * XSalsa20 / Poly1306 Tools and Constants.
 */
public class XSalsaTools
{
	public static final int KEY_LENGTH_BYTES = 256 / 8;
	public static final int NONCE_LENGTH_BYTES = 192 / 8;
	public static final int MAC_LENGTH_BYTES = 128 / 8;
	
	
	public static void encrypt(CByteArray key, CByteArray nonce, CByteArray input, CByteArray out, int offset, int length)
	{
		if(key.length() != KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		XSalsa20Engine engine = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				ParametersWithIV iv = new ParametersWithIV(kp, nonce);
				try
				{
					engine.init(true, iv);
				}
				finally
				{
					iv.zero();
				}
			}
			finally
			{
				kp.zero();
			}
			
			engine.processBytes(input, 0, length, out, offset);
		}
		finally
		{
			engine.zero();
		}
	}
	
	
	public static void encrypt(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, CByteArray cleartext, byte[] out, int outOffset)
	{
		if(key.length() != KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		XSalsa20Engine engine = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				ParametersWithIV param = new ParametersWithIV(kp, nonce, nonceOffset, nonceLength);
				try
				{
					engine.init(true, param);
				}
				finally
				{
					param.zero();
				}
			}
			finally
			{
				kp.zero();
			}
			
			engine.processBytes(cleartext, 0, cleartext.length(), out, outOffset);
		}
		finally
		{
			engine.zero();
		}
	}
	
	
	public static void decrypt(CByteArray key, CByteArray nonce, int offset, int length, CByteArray input, CByteArray out)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES * 8 + " bits");
		}

		XSalsa20Engine engine = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				ParametersWithIV param = new ParametersWithIV(kp, nonce);
				try
				{
					engine.init(false, param);
				}
				finally
				{
					param.zero();
				}
			}
			finally
			{
				kp.zero();
			}
			
			engine.processBytes(input, offset, length, out, 0);
		}
		finally
		{
			engine.zero();
		}
	}
	
	
	public static CByteArray decrypt(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, byte[] ciphertext, int offset, int length)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		XSalsa20Engine engine = new XSalsa20Engine();
		try
		{
			KeyParameter kp = new KeyParameter(key);
			try
			{
				ParametersWithIV param = new ParametersWithIV(kp, nonce, nonceOffset, nonceLength);
				try
				{
					engine.init(false, param);
				}
				finally
				{
					param.zero();
				}
			}
			finally
			{
				kp.zero();
			}
		
			CByteArray dec = new CByteArray(length);
			engine.processBytes(ciphertext, offset, length, dec, 0);
			return dec;
		}
		finally
		{
			engine.zero();
		}
	}
}
