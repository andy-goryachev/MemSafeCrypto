// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc.salsa;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * Encrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20EncryptStream
	extends OutputStream
{
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private OutputStream os;
	private byte[] out;


	public XSalsa20EncryptStream(byte[] key, byte[] nonce, OutputStream os)
	{
		if(key.length != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		this.os = os;
		this.out = new byte[XSalsaTools.BUFFER_SIZE];

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
		out[0] = (byte)b;
		xsalsa20.processBytes(out, 0, 1, out, 1);
		os.write(out, 1, 1);
	}


	public void write(byte[] b, int off, int len) throws IOException
	{
		int pos = 0;
		while(len > 0)
		{
			int sz = Math.min(len, out.length);
			xsalsa20.processBytes(b, off + pos, sz, out, 0);
			os.write(out, 0, sz);
			
			len -= sz;
			pos += sz;
		}
	}


	public void close() throws IOException
	{
		try
		{
			CKit.close(os);
		}
		finally
		{
			XSalsaTools.zero(xsalsa20);
			Crypto.zero(out);
			
			xsalsa20 = null;
			os = null;
		}			
	}
}