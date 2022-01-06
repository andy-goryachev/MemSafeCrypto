// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.eax;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;


public class EAXDecryptStream
	extends InputStream
{
	public static final int KEY_LENGTH_BYTES = 256/8;
	public static final int MAC_LEN_BITS = 64;
	public static final int BUFFER_SIZE = 64;
	private final KeyParameter keyParameter;
	private EAXBlockCipher cipher;
	private InputStream in;
	private byte[] buf;
	private byte[] out;
	private int pos;
	private int available;


	public EAXDecryptStream(byte[] key, byte[] nonce, byte[] associatedData, InputStream in)
	{
		if(key.length != KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES * 8 + " bits");
		}

		this.in = in;
		this.cipher = new EAXBlockCipher(new AESEngine());
		
		keyParameter = new KeyParameter(key);
		AEADParameters par = new AEADParameters(keyParameter, MAC_LEN_BITS, nonce, associatedData);

		cipher.init(false, par);

		out = new byte[BUFFER_SIZE];
		buf = new byte[BUFFER_SIZE];
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
		Crypto.zero(keyParameter);
		CKit.close(in);
		Crypto.zero(buf);
		Crypto.zero(out);

		cipher = null;
		buf = null;
		out = null;
	}


	/** for debugging */
	public InputStream getInputStream()
	{
		return in;
	}
}
