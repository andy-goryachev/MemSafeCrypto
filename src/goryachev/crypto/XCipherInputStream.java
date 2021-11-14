// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import goryachev.common.util.CKit;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;


public class XCipherInputStream
	extends InputStream
{
	private BufferedBlockCipher cipher;
	private BufferedInputStream in;
	private byte[] buf;
	private byte[] out;
	private int pos;
	private int available;


	public XCipherInputStream(BufferedBlockCipher c, CipherParameters p, InputStream in)
	{
		this.cipher = c;
		this.in = new BufferedInputStream(in);

		cipher.init(false, p);

		int sz = 512;
		out = new byte[sz];
		buf = new byte[sz];
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

		int b = out[pos++] & 0xff;
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

		System.arraycopy(out, pos, b, off, sz);

		pos += sz;
		available -= sz;

		return sz;
	}


	protected void load() throws IOException
	{
		pos = 0;

		if(in == null)
		{
			return;
		}

		try
		{
			while(available == 0)
			{
				int rd = in.read(buf);
				if(rd >= 0)
				{
					int n = cipher.processBytes(buf, 0, rd, out, 0);
					available += n;
				}
				else
				{
					int n = cipher.doFinal(out, 0);
					available += n;

					CKit.close(in);
					in = null;

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
		CKit.close(in);
		Crypto.zero(buf);
		Crypto.zero(out);
	}
}
