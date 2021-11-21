// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.ICryptoZeroable;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.IOException;


/**
 * Encrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20Encryptor
	implements ICryptoZeroable
{
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private CByteArray input;


	public XSalsa20Encryptor(CByteArray key, CByteArray nonce, CByteArray in)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		this.input = in;

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
	}
	
	
	public void encrypt(CByteArray out)
	{
		xsalsa20.processBytes(input, 0, out.length(), out, 0);
	}


	public void zero()
	{
		Crypto.zero(xsalsa20);
	}
}