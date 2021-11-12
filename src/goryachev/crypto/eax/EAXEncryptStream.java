// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.eax;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;


public class EAXEncryptStream
	extends OutputStream
{
	public static final int KEY_LENGTH_BYTES = 256/8;
	public static final int BUFFER_SIZE = 64; // why so short?
	private EAXBlockCipher cipher;
	private OutputStream os;
	private byte[] out;
	private KeyParameter keyParameter;


	public EAXEncryptStream(byte[] key, byte[] nonce, byte[] associatedData, OutputStream os)
	{
		if(key.length != KEY_LENGTH_BYTES)
		{
			throw new IllegalArgumentException("key must be " + KEY_LENGTH_BYTES*8 + " bits");
		}
		
		this.cipher = new EAXBlockCipher(new AESEngine());
		this.os = os;
		
		keyParameter = new KeyParameter(key);
		AEADParameters par = new AEADParameters(keyParameter, EAXDecryptStream.MAC_LEN_BITS, nonce, associatedData);

		cipher.init(true, par);
		
		out = new byte[BUFFER_SIZE];
	}


	public void write(int b) throws IOException
	{
		int rv = cipher.processByte((byte)b, out, 0);
		if(rv > 0)
		{
			os.write(out, 0, rv);
		}
	}


	public void write(byte[] b, int off, int len) throws IOException
	{
		int pos = 0;
		while(len > 0)
		{
			int sz = Math.min(len, out.length);
			int n = cipher.processBytes(b, off + pos, sz, out, 0);
			
			if(n > 0)
			{
				os.write(out, 0, n);
			}
			
			len -= sz;
			pos += sz;
		}
	}


	public void close() throws IOException
	{
		try
		{
			int n = cipher.doFinal(out, 0);
			if(n > 0)
			{
				os.write(out, 0, n);
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
		finally
		{
			try
			{
				CKit.close(os);
			}
			finally
			{
				Crypto.zero(keyParameter);
				Crypto.zero(out);
				
				cipher = null;
				os = null;
				keyParameter = null;
			}			
		}
	}
}