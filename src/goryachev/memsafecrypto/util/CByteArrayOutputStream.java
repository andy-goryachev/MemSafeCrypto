// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.ICryptoZeroable;
import java.io.IOException;
import java.io.OutputStream;


/**
 * CByteArray-based OutputStream implementation similar to ByteArrayOutputStream.
 */
public class CByteArrayOutputStream
	extends OutputStream
	implements ICryptoZeroable
{
	public static final int MAX_SIZE = Integer.MAX_VALUE - 64;
	private CByteArray buffer;
	private int size;


	public CByteArrayOutputStream(int capacity)
	{
		if(capacity < 0)
		{
			throw new IllegalArgumentException("Negative initial size: " + capacity);
		}
		buffer = new CByteArray(capacity);
	}


	public CByteArrayOutputStream()
	{
		this(256);
	}


	private void ensureCapacity(int cap)
	{
		if(cap > buffer.sizeInBytes())
		{
			grow(cap);
		}
	}


	private void grow(int requested)
	{
		if((requested < 0) || (requested > MAX_SIZE))
		{
			throw new OutOfMemoryError();
		}
		
		int cap = size << 1;
		if(cap < requested)
		{
			cap = requested;
		}
		
		CByteArray buf = new CByteArray(cap);
		buf.copyFrom(buffer, 0, size, 0);
		buffer = buf;
	}


	public synchronized void write(byte[] src, int offset, int length)
	{
		if((offset < 0) || (offset > src.length) || (length < 0) || ((offset + length) - src.length > 0))
		{
			throw new IndexOutOfBoundsException();
		}
		
		ensureCapacity(size + length);
		buffer.copyFrom(src, offset, length, size);
		size += length;
	}
	
	
	public synchronized void write(CByteArray src, int offset, int length)
	{
		if((offset < 0) || (offset > src.length()) || (length < 0) || ((offset + length) - src.length() > 0))
		{
			throw new IndexOutOfBoundsException();
		}
		
		ensureCapacity(size + length);
		buffer.copyFrom(src, offset, length, size);
		size += length;
	}


	public synchronized void write(int b)
	{
		ensureCapacity(size + 1);
		buffer.set(size++, (byte)b);
	}


	public synchronized CByteArray toCByteArray()
	{
		return new CByteArray(buffer, 0, size); 
	}


	public void close() throws IOException
	{
		buffer.zero();
	}


	public void zero()
	{
		buffer.zero();
	}
}
