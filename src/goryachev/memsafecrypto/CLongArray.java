// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable long[] equivalent based on DirectByteBuffer.
 */
public class CLongArray
	extends DirectArrayBase
{
	private static final int BYTES_PER_LONG = 8;
	
	
	public CLongArray(int capacity)
	{
		super(capacity * BYTES_PER_LONG);
	}
	
	
	public CLongArray(CLongArray x)
	{
		super(x);
	}
	
	
	public int length()
	{
		return sizeInBytes() / BYTES_PER_LONG;
	}


	public void add(int index, long value)
	{
		checkWriteable();

		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v += value;
		buffer.putLong(ix, value);
	}
	
	
	public void subtract(int index, long value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v -= value;
		buffer.putLong(ix, v);
	}
	
	
	public void xor(int index, long value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v ^= value;
		buffer.putLong(ix, v);
	}
	
	
	public void increment(int index)
	{
		checkWriteable();

		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v++;
		buffer.putLong(ix, v);
	}
	
	
	public long incrementAndGet(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v++;
		buffer.putLong(ix, v);
		return v;
	}
	
	
	public void decrement(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v--;
		buffer.putLong(ix, v);
	}
	
	
	public long decrementAndGet(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		long v = buffer.getLong(ix);
		v--;
		buffer.putLong(ix, v);
		return v;
	}
	
	
	public long get(int index)
	{
		int ix = index * BYTES_PER_LONG;
		return buffer.getLong(ix);
	}
	
	
	public void set(int index, long value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		buffer.putLong(ix, value);
	}
	
	
	public void fill(long value)
	{
		checkWriteable();
		
		int sz = length();
		for(int i=0; i<sz; i++)
		{
			int ix = i * BYTES_PER_LONG;
			buffer.putLong(ix, value);
		}
	}


	public void copy(int toOffset, long[] src, int srcOffset, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			long v = src[i + srcOffset];
			int ix = (i + toOffset) * BYTES_PER_LONG;
			buffer.putLong(ix, v);
		}
	}
	
	
	public void copy(int toOffset, CLongArray src, int srcOffset, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			long v = src.get(i + srcOffset);
			int ix = (i + toOffset) * BYTES_PER_LONG;
			buffer.putLong(ix, v);
		}
	}
	
	
	public long[] toArray()
	{
		int len = length();
		long[] rv = new long[len];
		for(int i=0; i<len; i++)
		{
			rv[i] = get(i);
		}
		return rv;
	}
}
