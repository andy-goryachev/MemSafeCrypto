// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.xsalsa20poly1305;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * Encrypting Stream Based on Xsalsa20poly1305 Scheme.
 */
public class XSalsa20Poly1305EncryptStream
	extends OutputStream
{
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private Poly1305 poly1305 = new Poly1305();
	private OutputStream os;
	private byte[] out;


	public XSalsa20Poly1305EncryptStream(byte[] key, byte[] nonce, OutputStream os)
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
		
		byte[] subkey = new byte[XSalsaTools.KEY_LENGTH_BYTES];
		try
		{
			xsalsa20.processBytes(subkey, 0, XSalsaTools.KEY_LENGTH_BYTES, subkey, 0);
			
			KeyParameter kp = new KeyParameter(subkey);
			try
			{
				poly1305.init(kp);
			}
			finally
			{
				Crypto.zero(kp);
			}
		}
		finally
		{
			Crypto.zero(subkey);
		}
	}
	

	public void write(int b) throws IOException
	{
		out[0] = (byte)b;
		xsalsa20.processBytes(out, 0, 1, out, 1);
		poly1305.update(out, 1, 1);
		os.write(out, 1, 1);
	}


	public void write(byte[] b, int off, int len) throws IOException
	{
		int pos = 0;
		while(len > 0)
		{
			int sz = Math.min(len, out.length);
			xsalsa20.processBytes(b, off + pos, sz, out, 0);
			poly1305.update(out, 0, sz);
			os.write(out, 0, sz);
			
			len -= sz;
			pos += sz;
		}
	}


	public void close() throws IOException
	{
		try
		{
			poly1305.doFinal(out, 0);
			os.write(out, 0, poly1305.getMacSize());
		}
		catch(IOException e)
		{
			throw e;
		}
		catch(Exception e)
		{
			throw new IOException(e);
		}
		finally
		{
			try
			{
				CKit.close(os);
			}
			finally
			{
				XSalsaTools.zero(xsalsa20);
				XSalsaTools.zero(poly1305);
				Crypto.zero(out);
				
				xsalsa20 = null;
				poly1305 = null;
				os = null;
			}			
		}
	}
}