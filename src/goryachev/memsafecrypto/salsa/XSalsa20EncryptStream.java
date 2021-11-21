// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.IOException;
import java.io.OutputStream;


/**
 * Encrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20EncryptStream
	extends OutputStream
{
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private CByteArray os;
	private CByteArray out;


	public XSalsa20EncryptStream(CByteArray key, CByteArray nonce, CByteArray os)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		this.os = os;
		this.out = new CByteArray(XSalsaTools.BUFFER_SIZE);

		KeyParameter keyParameter = new KeyParameter(key);
		try
		{
			ParametersWithIV iv = new ParametersWithIV(keyParameter, nonce);
			xsalsa20.init(true, iv);
		}
		finally
		{
			Crypto.zero(keyParameter);
		}
	}
	

	public void write(int b) throws IOException
	{
		out.set(0, (byte)b);
		xsalsa20.processBytes(out, 0, 1, out, 1);
		os.write(out, 1, 1);
	}


	public void write(byte[] b, int off, int len) throws IOException
	{
		int pos = 0;
		while(len > 0)
		{
			int sz = Math.min(len, out.length());
			xsalsa20.processBytes(b, off + pos, sz, out, 0);
			os.write(out, 0, sz);
			
			len -= sz;
			pos += sz;
		}
	}
	
	
	public void write(CByteArray b) throws IOException
	{
		write(b, 0, b.length());
	}
	
	
	public void write(CByteArray b, int off, int len) throws IOException
	{
		int pos = 0;
		while(len > 0)
		{
			int sz = Math.min(len, out.length());
			xsalsa20.processBytes(b, off + pos, sz, out, 0);
			os.write(out, 0, sz);
			
			len -= sz;
			pos += sz;
		}
	}


	public void close() throws IOException
	{
		Crypto.zero(xsalsa20);
		Crypto.zero(out);
		
		xsalsa20 = null;
		os = null;
	}
}