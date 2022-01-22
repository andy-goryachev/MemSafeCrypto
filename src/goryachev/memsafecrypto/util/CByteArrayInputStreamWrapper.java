// Copyright © 2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.CByteArray;
import java.io.IOException;
import java.io.InputStream;


/**
 * CByteArray-based InputStream which wraps (i.e. does not copy) a CByteArray.
 * Because it is a wrapper, the close() does nothing and the underlying CByteArray
 * must not be zeroed while this object is being used.
 */
public class CByteArrayInputStreamWrapper
	extends InputStream
{
	private final CByteArray buffer;
	private final int start;
	private int position;
	private int size;
	
	
	public CByteArrayInputStreamWrapper(CByteArray b, int offset, int length)
	{
		this.buffer = b;
		this.start = offset;
		this.size = Math.min(offset + length, b.length());
	}
	
	
	public CByteArrayInputStreamWrapper(CByteArray b)
	{
		this(b, 0, b.length());
	}
	
	
	public int getPosition()
	{
		return position;
	}


	public synchronized int read()
	{
		if(position < size)
		{
			return buffer.get(start + position++) & 0xff;
		}
		else
		{
			return -1;
		}
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

		if(position >= size)
		{
			return -1;
		}

		int available = size - position;
		if(len > available)
		{
			len = available;
		}
		
		if(len <= 0)
		{
			return 0;
		}
		
		for(int i=0; i<len; i++)
		{
			b[off + i] = buffer.get(start + position++);
		}
		return len;
	}


	public synchronized long skip(long n)
	{
		long p = size - position;
		if(n < p)
		{
			p = n < 0 ? 0 : n;
		}

		position += p;
		return p;
	}


	public synchronized int available()
	{
		return size - position;
	}


	public void close() throws IOException
	{
	}
}
