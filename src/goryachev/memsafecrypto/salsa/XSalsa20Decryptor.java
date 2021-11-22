// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * Decrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20Decryptor
{
	public static void decrypt(CByteArray key, CByteArray nonce, int offset, int length, CByteArray input, CByteArray out)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}

		XSalsa20Engine xsalsa20 = new XSalsa20Engine();
		try
		{
			KeyParameter keyParameter = new KeyParameter(key);
			try
			{
				ParametersWithIV iv = new ParametersWithIV(keyParameter, nonce);
				xsalsa20.init(false, iv);
			}
			finally
			{
				keyParameter.zero();
			}
			
			xsalsa20.processBytes(input, offset, length, out, 0);
		}
		finally
		{
			xsalsa20.zero();
		}
	}
}
