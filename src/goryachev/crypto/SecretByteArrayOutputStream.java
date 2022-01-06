// Copyright © 2012-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;


/**
 * Slightly more secure implementation of ByteArrayOutputStream
 */
public final class SecretByteArrayOutputStream
	extends OutputStream
{
	private byte[] buf;
	private int size;


	public SecretByteArrayOutputStream()
	{
		this(64);
	}


	public SecretByteArrayOutputStream(int size)
	{
		if(size < 0)
		{
			throw new IllegalArgumentException("Negative size: " + size);
		}
		buf = new byte[size];
	}


	private void ensureCapacity(int minCapacity)
	{
		if(minCapacity - buf.length > 0)
		{
			grow(minCapacity);
		}
	}


	private void grow(int minCapacity)
	{
		int oldCapacity = buf.length;
		int newCapacity = oldCapacity << 1;
		if(newCapacity - minCapacity < 0)
		{
			newCapacity = minCapacity;
		}
		if(newCapacity < 0)
		{
			if(minCapacity < 0)
			{
				throw new OutOfMemoryError();
			}
			newCapacity = Integer.MAX_VALUE;
		}
		
		byte[] b = Arrays.copyOf(buf, newCapacity);
		Crypto.zero(buf);
		buf = b;
	}


	public synchronized void write(int b)
	{
		ensureCapacity(size + 1);
		buf[size] = (byte)b;
		size += 1;
	}


	public synchronized void write(byte[] b, int off, int len)
	{
		if((off < 0) || (off > b.length) || (len < 0) || ((off + len) - b.length > 0))
		{
			throw new IndexOutOfBoundsException();
		}
		
		ensureCapacity(size + len);
		System.arraycopy(b, off, buf, size, len);
		size += len;
	}


	public synchronized void writeTo(OutputStream out) throws IOException
	{
		out.write(buf, 0, size);
	}


	public synchronized void reset()
	{
		size = 0;
	}


	public synchronized byte[] toByteArray()
	{
		return Arrays.copyOf(buf, size);
	}


	public synchronized int size()
	{
		return size;
	}


	public void close() throws IOException
	{
		Crypto.zero(buf);
	}
}
