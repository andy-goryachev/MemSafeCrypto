// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.Poly1305;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import goryachev.memsafecrypto.util.CUtils;


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
	
	
	/** encrypts a CByteArray into a CByteArray with authenticated XSalsa20Poly1305 cipher */
	public static CByteArray encryptXSalsa20Poly1305(CByteArray key, CByteArray nonce, CByteArray input)
	{
		return encryptXSalsa20Poly1305(key, nonce, 0, input, 0, input.length());
	}
	
	
	/** encrypts a CByteArray into a CByteArray with authenticated XSalsa20Poly1305 cipher */
	public static CByteArray encryptXSalsa20Poly1305(CByteArray key, CByteArray nonce, int nonceOffset, CByteArray input, int inputOffset, int inputLength)
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
				ParametersWithIV param = new ParametersWithIV(kp, nonce, nonceOffset, NONCE_LENGTH_BYTES);
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
				
				CByteArray out = new CByteArray(inputLength + MAC_LENGTH_BYTES);
				engine.processBytes(input, inputOffset, inputLength, out, 0);
				poly1305.update(out, 0, inputLength);
				poly1305.doFinal(out, inputLength);
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
	
	
	/** decrypts a CByteArray into a CByteArray with authenticated XSalsa20Poly1305 cipher */
	public static CByteArray decryptXSalsa20Poly1305(CByteArray key, CByteArray nonce, CByteArray input) throws Exception
	{
		return decryptXSalsa20Poly1305(key, nonce, 0, input, 0, input.length());
	}
	
	
	/** decrypts a CByteArray into a CByteArray with authenticated XSalsa20Poly1305 cipher */
	public static CByteArray decryptXSalsa20Poly1305(CByteArray key, CByteArray nonce, int nonceOffset, CByteArray input, int inputOffset, int inputLength) throws Exception
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
				ParametersWithIV param = new ParametersWithIV(kp, nonce, nonceOffset, NONCE_LENGTH_BYTES);
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
			
			Poly1305 poly1305 = new Poly1305();
			try
			{
				CByteArray subkey = new CByteArray(KEY_LENGTH_BYTES);
				try
				{
					engine.processBytes(subkey, 0, subkey.length(), subkey, 0);
					
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
				
				int len = inputLength - MAC_LENGTH_BYTES;
				CByteArray out = new CByteArray(len);
				
				poly1305.update(input, inputOffset, len);
				engine.processBytes(input, inputOffset, len, out, 0);
				
				// compute mac
				CByteArray mac = new CByteArray(MAC_LENGTH_BYTES);
				poly1305.doFinal(mac, 0);
				
				if(!CUtils.compareConstantTime(mac, 0, MAC_LENGTH_BYTES, input, len))
				{
					out.zero();
					throw new Exception("MAC mismatch");
				}
				
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
