// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.Poly1305;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * XSalsa20 / Poly1306 Tools and Constants.
 */
public class XSalsaTools
{
	public static final int KEY_LENGTH_BYTES = 256 / 8;
	public static final int NONCE_LENGTH_BYTES = 192 / 8;
	public static final int MAC_LENGTH_BYTES = 128 / 8;
	
	
	/** encrypts a CByteArray into a CByteArray with non-authenticated XSalsa20 cipher */
	public static void encryptXSalsa20(CByteArray key, CByteArray nonce, CByteArray input, CByteArray out, int offset, int length)
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
	
	
	/** encrypts a CByteArray into a byte[] with non-authenticated XSalsa20 cipher */
	public static void encryptXSalsa20(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, CByteArray cleartext, byte[] out, int outOffset)
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
	
	
	/** decrypts a CByteArray into a CByteArray with non-authenticated XSalsa20 cipher */
	public static void decryptXSalsa20(CByteArray key, CByteArray nonce, int offset, int length, CByteArray input, CByteArray out)
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
	
	
	/** decrypts a byte[] into a CByteArray with non-authenticated XSalsa20 cipher */
	public static CByteArray decryptXSalsa20(CByteArray key, byte[] nonce, int nonceOffset, int nonceLength, byte[] ciphertext, int offset, int length)
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
	
	
	/** encrypts a CByteArray into a CByteArray with non-authenticated XSalsa20 cipher */
	public CByteArray encryptXSalsa20Poly1305(CByteArray key, CByteArray nonce, CByteArray input)
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
				ParametersWithIV param = new ParametersWithIV(kp, nonce);
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
			
			Poly1305 poly1305 = new Poly1305();
			try
			{
				CByteArray subkey = new CByteArray(KEY_LENGTH_BYTES);
				try
				{
					engine.processBytes(subkey, 0, KEY_LENGTH_BYTES, subkey, 0);
					
					KeyParameter skp = new KeyParameter(subkey);
					try
					{
						poly1305.init(skp);
					}
					finally
					{
						skp.zero();
					}
				}
				finally
				{
					subkey.zero();
				}
				
				int len = input.length();
				CByteArray out = new CByteArray(len + MAC_LENGTH_BYTES);
				engine.processBytes(input, 0, len, out, 0);
				poly1305.update(out, 0, len);
				poly1305.doFinal(out, len);
				return out;
			}
			finally
			{
				poly1305.zero();
			}
		}
		finally
		{
			engine.zero();
		}
	}
}
