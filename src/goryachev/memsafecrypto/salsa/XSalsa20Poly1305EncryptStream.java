// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.Poly1305;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.IOException;
import java.io.OutputStream;


/**
 * Encrypting Stream Based on XSalsa20/Poly1305 Scheme.
 */
public class XSalsa20Poly1305EncryptStream
	extends OutputStream
{
	private static final int BUFFER_SIZE = 4096;
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private Poly1305 poly1305 = new Poly1305();
	private OutputStream os;
	private byte[] out;


	public XSalsa20Poly1305EncryptStream(CByteArray key, CByteArray nonce, OutputStream os)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}
		
		this.os = os;
		this.out = new byte[BUFFER_SIZE];

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
		
		CByteArray subkey = new CByteArray(XSalsaTools.KEY_LENGTH_BYTES);
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
				kp.zero();
			}
		}
		finally
		{
			subkey.zero();
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
				xsalsa20.zero();
				poly1305.zero();
				Crypto.zero(out);
				
				xsalsa20 = null;
				poly1305 = null;
				os = null;
			}			
		}
	}
}