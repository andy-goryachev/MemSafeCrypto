// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.ICryptoZeroable;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;


/**
 * Decrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20Decryptor
	implements ICryptoZeroable
{
	public static final int BUFFER_SIZE = 4096;
	private CByteArray in;
	private int offset;
	private int length;
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();


	public XSalsa20Decryptor(CByteArray key, CByteArray nonce, int offset, int length, CByteArray in)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}

		this.in = in;
		this.offset = offset;
		this.length = length;
		
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
	}
	

	public void decrypt(CByteArray out) throws Exception
	{
		xsalsa20.processBytes(in, offset, length, out, 0);
	}
	

	public void zero()
	{
		xsalsa20.zero();
	}
}
