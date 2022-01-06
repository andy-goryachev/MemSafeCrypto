// Copyright © 2020-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.io.CIOTools;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.IOException;
import java.io.OutputStream;


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
	private final byte[] smallBuffer = new byte[8];
	
	
	public XSalsaOutputStream(OutputStream out, CByteArray key, CByteArray iv)
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
		CIOTools.longToBytes(smallBuffer, x);
		write(smallBuffer, 0, 8);
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
		smallBuffer[0] = (byte)b;
		write(smallBuffer, 0, 1);
	}


	public void close() throws IOException
	{
		Crypto.zero(keyParameter);
		Crypto.zero(paramIV);
		CKit.close(out);
		Crypto.zero(smallBuffer);
	}
}
