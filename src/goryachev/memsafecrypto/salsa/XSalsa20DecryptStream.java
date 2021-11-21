// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.IOException;
import java.io.InputStream;


/**
 * Decrypting Stream Based on XSalsa20 Engine.
 */
public class XSalsa20DecryptStream
	extends InputStream
{
	public static final int BUFFER_SIZE = 4096;
	private InputStream in;
	private long toRead;
	private byte[] buf;
	private CByteArray out;
	private int index;
	private int available;
	private XSalsa20Engine xsalsa20 = new XSalsa20Engine();


	public XSalsa20DecryptStream(CByteArray key, CByteArray nonce, long cipherTextLength, InputStream in)
	{
		if(key.length() != XSalsaTools.KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + XSalsaTools.KEY_LENGTH_BYTES * 8 + " bits");
		}

		this.in = in;
		this.toRead = cipherTextLength;
		this.out = new CByteArray(BUFFER_SIZE);
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
