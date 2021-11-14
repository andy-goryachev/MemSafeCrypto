// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import goryachev.common.util.CKit;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;


public class XCipherOutputStream
	extends OutputStream
{
	private BufferedBlockCipher cipher;
	private OutputStream os;
	private byte[] out;


	public XCipherOutputStream(BufferedBlockCipher c, CipherParameters p, OutputStream os)
	{
		this.cipher = c;
		this.os = os;
		
		cipher.init(true, p);
		
		out = new byte[512];
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

			os.flush();
			CKit.close(os);
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
			Crypto.zero(out);
			cipher = null;
			os = null;
		}
	}
}