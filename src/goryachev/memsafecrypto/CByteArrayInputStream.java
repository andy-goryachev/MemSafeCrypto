// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.io.IOException;
import java.io.InputStream;


/**
 * CByteArray InputStream.
 */
public class CByteArrayInputStream
	extends InputStream
{
	protected CByteArray buffer;
	protected int size;
	protected int position;
	protected int mark;


	public CByteArrayInputStream(CByteArray buf)
	{
		this.buffer = buf;
		this.size = buf.length();
		this.position = 0;
	}


	public CByteArrayInputStream(byte[] buf, int offset, int length)
	{
		this.buffer = CByteArray.readOnly(buf, offset, length);
		this.size = Math.min(offset + length, buf.length);
		this.position = offset;
		this.mark = offset;
	}


	public synchronized int read()
	{
		if(position < size)
		{
			return buffer.get(position++) & 0xff;
		}
		return -1;
	}


	public synchronized int read(byte[] target, int offset, int length)
	{
		if(target == null)
		{
			throw new NullPointerException();
		}
		else if
		(
			length < 0 || 
			offset < 0 || 
			(length > (target.length - offset))
		)
		{
			throw new IndexOutOfBoundsException();
		}
		else if(position >= size)
		{
			return -1;
		}

		int available = size - position;
		if(length > available)
		{
			length = available;
		}
		
		if(length <= 0)
		{
			return 0;
		}
		
		for(int i=0; i<length; i++)
		{
			byte b = buffer.get(i + position);
			target[i + offset] = b;
			position++;
		}
		
		return length;
	}


	public synchronized long skip(long n)
	{
		long k = size - position;
		if(n < k)
		{
			k = n < 0 ? 0 : n;
		}

		position += k;
		return k;
	}


	public synchronized int available()
	{
		return size - position;
	}


	public boolean markSupported()
	{
		return true;
	}


	public synchronized void mark(int readlimit)
	{
		mark = position;
	}


	public synchronized void reset()
	{
		position = mark;
	}


	public void close() throws IOException
	{
	}
}
