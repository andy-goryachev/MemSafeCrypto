// Copyright © 2020-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.salsa;
import goryachev.common.io.CIOTools;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.bc.KeyParameter;
import goryachev.memsafecrypto.bc.ParametersWithIV;
import goryachev.memsafecrypto.bc.XSalsa20Engine;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;


/**
 * RandomAccessFile encrypted with XSalsa20Engine cipher.
 * This implementation is not synchronized.
 */
public class XSalsaRandomAccessFile
	implements Closeable
{
	protected static final int BUFFER_LENGTH = 4096;
	private final File file;
	private final boolean forWriting;
	private final RandomAccessFile raf;
	private final XSalsa20Engine engine;
	private final KeyParameter keyParameter;
	private final ParametersWithIV paramIV;
	private final byte[] buffer = new byte[BUFFER_LENGTH];
	private final byte[] databuf = new byte[8];
	
	
	public XSalsaRandomAccessFile(File file, boolean forWriting, CByteArray key, CByteArray iv) throws FileNotFoundException
	{
		this.file = file;
		this.forWriting = forWriting;
		this.raf = new RandomAccessFile(file, forWriting ? "rw" : "r");
		this.engine = new XSalsa20Engine();
		
		// init engine
		keyParameter = new KeyParameter(key);
		paramIV = new ParametersWithIV(keyParameter, iv);
		engine.init(forWriting, paramIV);
	}


	public void seek(long offset) throws IOException
	{
		engine.seekTo(offset);
		raf.seek(offset);
	}


	/** may read less than 'len' bytes, just like InputStream */
	public int read(byte[] buf, int off, int len) throws IOException
	{
		int sz = Math.min(BUFFER_LENGTH, len);
		int rd = raf.read(buffer, 0, sz);
		if(rd < 0)
		{
			return -1;
		}
		else if(rd == 0)
		{
			return 0;
		}

		engine.processBytes(buffer, 0, rd, buf, off);
		return rd;
	}
	
	
	public int read(byte[] buf) throws IOException
	{
		return read(buf, 0, buf.length);
	}


	public void readFully(byte[] buf) throws IOException
	{
		readFully(buf, 0, buf.length);
	}


	public void readFully(byte[] buf, int off, int len) throws IOException
	{
		int read = 0;
		do
		{
			int ct = read(buf, off + read, len - read);
			if(ct < 0)
			{
				throw new EOFException("premature EOF");
			}
			
			read += ct;
		} while(read < len);
	}


	public long readLong() throws IOException
	{
		readFully(databuf, 0, 8);
		return CIOTools.bytesToLong(databuf);
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
		if(!forWriting)
		{
			throw new Error("!forWriting");
		}
		
		int offset = 0;
		int toWrite = len;
		while(toWrite > 0)
		{
			int sz = Math.min(BUFFER_LENGTH, toWrite);

			engine.processBytes(buf, off + offset, sz, buffer, 0);
			raf.write(buffer, 0, sz);
			
			offset += sz;
			toWrite -= sz;
		}
	}


	public void write(byte[] buf) throws IOException
	{
		write(buf, 0, buf.length);
	}
	
	
	/**
	 * Writes bytes to the file as is, unencryped.
	 * This method does advance the position in the encryption engine,
	 * unless the write operation throws an exception.
	 * When that happens, the position is reset to the value it had
	 * prior to this call.
	 */ 
	public void writeUnencrypted(byte[] buf) throws IOException
	{
		long pos = raf.getFilePointer();
		try
		{
			raf.write(buf);
			pos = -1L;
			engine.skip(buf.length);
		}
		finally
		{
			if(pos >= 0L)
			{
				seek(pos);
			}
		}		
	}
	

	/**
	 * Reads bytes from the file as is, unencrypted.
	 * This method does advance the position in the encryption engine,
	 * unless the read operation throws an exception.
	 * When that happens, the position is reset to the value it had
	 * prior to this call.
	 */
	public void readUnencrypted(byte[] buf) throws IOException
	{
		long pos = raf.getFilePointer();
		try
		{
			raf.readFully(buf);
			pos = -1L;
			engine.skip(buf.length);
		}
		finally
		{
			if(pos >= 0L)
			{
				seek(pos);
			}
		}
	}


	public void close() throws IOException
	{
		Crypto.zero(keyParameter);
		Crypto.zero(paramIV);
		CKit.close(raf);
	}
}
