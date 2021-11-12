// Copyright © 2020-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.file;
import goryachev.common.io.CIOTools;
import goryachev.common.util.CKit;
import goryachev.crypto.Crypto;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * OutputStream encrypted with XSalsa20Engine cipher.
 * This implementation is not synchronized.
 */
public class XSalsaOutputStream
	extends OutputStream
{
	protected static final int BUFFER_LENGTH = 4096;
	private final OutputStream out;
	private final XSalsa20Engine engine;
	private final KeyParameter keyParameter;
	private final ParametersWithIV paramIV;
	private final byte[] buffer = new byte[BUFFER_LENGTH];
	private final byte[] databuf = new byte[8];
	
	
	public XSalsaOutputStream(OutputStream out, byte[] key, byte[] iv) throws FileNotFoundException
	{
		this.out = out;
		this.engine = new XSalsa20Engine();
		
		// init engine
		keyParameter = new KeyParameter(key);
		paramIV = new ParametersWithIV(keyParameter, iv);
		engine.init(true, paramIV);
	}

	
	public void writeLong(long x) throws IOException
	{
		CIOTools.longToBytes(databuf, x);
		write(databuf, 0, 8);
	}
	
	
	public void writeText(String text) throws IOException
	{
		byte[] b = text.getBytes(CKit.CHARSET_UTF8);
		write(b, 0, b.length);
	}
	

	public void write(byte[] buf, int off, int len) throws IOException
	{
		int offset = 0;
		int toWrite = len;
		while(toWrite > 0)
		{
			int sz = Math.min(BUFFER_LENGTH, toWrite);

			engine.processBytes(buf, off + offset, sz, buffer, 0);
			out.write(buffer, 0, sz);
			
			offset += sz;
			toWrite -= sz;
		}
	}


	public void write(byte[] buf) throws IOException
	{
		write(buf, 0, buf.length);
	}
	
	
	public void write(int b) throws IOException
	{
		databuf[0] = (byte)b;
		write(databuf, 0, 1);
	}


	public void close() throws IOException
	{
		Crypto.zero(keyParameter.getKey());
		Crypto.zero(paramIV.getIV());
		CKit.close(out);
	}
}
