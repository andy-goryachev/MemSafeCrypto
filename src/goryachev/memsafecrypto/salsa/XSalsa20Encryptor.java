// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * A single shot encryptor based on XSalsa20 Engine.
 */
public class XSalsa20Encryptor
{
	public static void encrypt(CByteArray key, CByteArray nonce, CByteArray input, CByteArray out, int offset, int length)
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
				xsalsa20.init(true, iv);
			}
			finally
			{
				keyParameter.zero();
			}
			
			xsalsa20.processBytes(input, 0, length, out, offset);
		}
		finally
		{
			Crypto.zero(xsalsa20);
		}
	}
}