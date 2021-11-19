// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;


/**
 * Zeroable long[] equivalend based on DirectByteBuffer.
 */
public class CLongArray
	extends DirectArrayBase
{
	private static final int BYTES_PER_LONG = 8;
	
	
	public CLongArray(int capacity)
	{
		super(capacity * BYTES_PER_LONG);
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
		return buffer.getInt(ix);
	}
	
	
	public void set(int index, long value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_LONG;
		buffer.putLong(ix, value);
	}
}
