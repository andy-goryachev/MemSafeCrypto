// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.xsalsa20poly1305;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * Decrypting Stream Based on Xsalsa20poly1305 Scheme.
 */
public class XSalsa20Poly1305DecryptStream
	extends InputStream
{
	public static final int BUFFER_SIZE = 4096;
	private InputStream in;
	private long toRead;
	private byte[] buf;
	private byte[] out;
	private int index;
	private int available;
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private Poly1305 poly1305 = new Poly1305();


	public XSalsa20Poly1305DecryptStream(byte[] key, byte[] nonce, long cipherTextLength, InputStream in)
	{
		if(key.length != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}

		this.in = in;
		this.toRead = cipherTextLength - poly1305.getMacSize();
		this.out = new byte[BUFFER_SIZE];
		this.buf = new byte[BUFFER_SIZE];
		
		KeyParameter keyParameter = new KeyParameter(key);
		try
		{
			ParametersWithIV iv = new ParametersWithIV(keyParameter, nonce);
			xsalsa20.init(false, iv);
		}
		finally
		{
			Crypto.zero(keyParameter);
		}
		
		byte[] subkey = new byte[XSalsaTools.KEY_LENGTH_BYTES];
		try
		{
			xsalsa20.processBytes(subkey, 0, subkey.length, subkey, 0);
			
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
	

	public int read() throws IOException
	{
		if(available == 0)
		{
			load();

			if(available == 0)
			{
				return -1;
			}
		}

		int b = out[index++] & 0xff;
		available--;

		return b;
	}


	public int read(byte b[], int off, int len) throws IOException
	{
		if(available == 0)
		{
			load();

			if(available == 0)
			{
				return -1;
			}
		}

		int sz = Math.min(available, len);

		System.arraycopy(out, index, b, off, sz);

		index += sz;
		available -= sz;

		return sz;
	}


	protected void load() throws IOException
	{
		index = 0;

		if(in == null)
		{
			return;
		}

		try
		{
			while(available == 0)
			{
				int sz = (int)Math.min(buf.length, toRead);
				if(sz > 0)
				{
					CKit.checkCancelled();
					
					int rd = in.read(buf, 0, sz);
					if(rd == 0)
					{
						CKit.sleep(10);
						continue;
					}
					else if(rd > 0)
					{
						poly1305.update(buf, 0, rd);
						xsalsa20.processBytes(buf, 0, rd, out, 0);
						available += rd;
						toRead -= rd;
						continue;
					}
					else
					{
						throw new IOException("premature EOF");
					}
				}
				else
				{
					if(toRead != 0)
					{
						throw new Error("toRead=" + toRead);
					}
					
					// compute mac
					byte[] mac = new byte[poly1305.getMacSize()];
					poly1305.doFinal(mac, 0);
					
					// read mac from input
					byte[] mac2 = new byte[poly1305.getMacSize()];
					CKit.readFully(in, mac2);
					
					if(!MessageDigest.isEqual(mac, mac2))
					{
						throw new IOException("MAC mismatch");
					}

					return;
				}
			}
		}
		catch(IOException e)
		{
			throw e;
		}
		catch(Exception e)
		{
			throw new IOException(e);
		}
	}


	public void close() throws IOException
	{
		XSalsaTools.zero(xsalsa20);
		XSalsaTools.zero(poly1305);
		
		CKit.close(in);
		Crypto.zero(buf);
		Crypto.zero(out);

		buf = null;
		out = null;
	}


	/** for debugging */
	public InputStream getInputStream()
	{
		return in;
	}
}
