// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.Poly1305;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import goryachev.memsafecrypto.util.CUtils;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;


/**
 * Decrypting Stream Based on XSalsa20/Poly1305 Scheme.
 */
public class XSalsa20Poly1305DecryptStream
	extends InputStream
{
	private static final int BUFFER_SIZE = 4096;
	private InputStream in;
	private long toRead;
	private byte[] buf;
	private CByteArray out;
	private int index;
	private int available;
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();
	private Poly1305 poly1305 = new Poly1305();


	public XSalsa20Poly1305DecryptStream(CByteArray key, CByteArray nonce, long cipherTextLength, InputStream in)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}

		this.in = in;
		this.toRead = cipherTextLength - poly1305.getMacSize();
		this.out = new CByteArray(BUFFER_SIZE);
		this.buf = new byte[BUFFER_SIZE];
		
		KeyParameter kp = new KeyParameter(key);
		try
		{
			ParametersWithIV param = new ParametersWithIV(kp, nonce);
			try
			{
				xsalsa20.init(false, param);
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
		
		CByteArray subkey = new CByteArray(XSalsaTools.KEY_LENGTH_BYTES);
		try
		{
			xsalsa20.processBytes(subkey, 0, subkey.length(), subkey, 0);
			
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

		int b = out.get(index++) & 0xff;
		available--;

		return b;
	}


	public int read(byte[] b, int off, int len) throws IOException
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

		CUtils.arraycopy(out, index, b, off, sz);

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
		Crypto.zero(xsalsa20);
		Crypto.zero(poly1305);
		
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
