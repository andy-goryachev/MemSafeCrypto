// Copyright © 2012-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import java.io.IOException;
import java.io.InputStream;


/**
 * Slightly more secure implementation of ByteArrayInputStream.  
 * The client code must reset the input array when done.
 */
public final class SecretByteArrayInputStream
	extends InputStream
{
	private byte[] buf;
	private int pos;
	private int mark;
	private int count;


	public SecretByteArrayInputStream(byte[] buf)
	{
		this.buf = buf;
		this.pos = 0;
		this.count = buf.length;
	}


	public SecretByteArrayInputStream(byte[] buf, int offset, int length)
	{
		this.buf = buf;
		this.pos = offset;
		this.count = Math.min(offset + length, buf.length);
		this.mark = offset;
	}


	public synchronized int read()
	{
		return (pos < count) ? (buf[pos++] & 0xff) : -1;
	}


	public synchronized int read(byte[] b, int off, int len)
	{
		if(b == null)
		{
			throw new NullPointerException();
		}
		else if(off < 0 || len < 0 || len > b.length - off)
		{
			throw new IndexOutOfBoundsException();
		}

		if(pos >= count)
		{
			return -1;
		}

		int avail = count - pos;
		if(len > avail)
		{
			len = avail;
		}
		if(len <= 0)
		{
			return 0;
		}
		System.arraycopy(buf, pos, b, off, len);
		pos += len;
		return len;
	}


	public synchronized long skip(long sz)
	{
		long ix = count - pos;
		if(sz < ix)
		{
			ix = sz < 0 ? 0 : sz;
		}

		pos += ix;
		return ix;
	}


	public synchronized int available()
	{
		return count - pos;
	}


	public boolean markSupported()
	{
		return true;
	}


	public synchronized void mark(int readlimit)
	{
		mark = pos;
	}


	public synchronized void reset()
	{
		pos = mark;
	}


	public void close() throws IOException
	{
	}
}
