// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;


/**
 * Zeroable int[] equivalend based on DirectByteBuffer.
 */
public class IntArray
	extends DirectArrayBase
{
	private static final int BYTES_PER_INT = 4;
	
	
	public IntArray(int capacity)
	{
		super(capacity * BYTES_PER_INT);
	}
	
	
	public int length()
	{
		return sizeInBytes() / BYTES_PER_INT;
	}


	public void add(int index, int value)
	{
		checkWriteable();

		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v += value;
		buffer.putInt(ix, value);
	}
	
	
	public void subtract(int index, int value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v -= value;
		buffer.putInt(ix, v);
	}
	
	
	public void increment(int index)
	{
		checkWriteable();

		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v++;
		buffer.putInt(ix, v);
	}
	
	
	public int incrementAndGet(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v++;
		buffer.putInt(ix, v);
		return v;
	}
	
	
	public void decrement(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v--;
		buffer.putInt(ix, v);
	}
	
	
	public int decrementAndGet(int index)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_INT;
		int v = buffer.getInt(ix);
		v--;
		buffer.putInt(ix, v);
		return v;
	}
	
	
	public int get(int index)
	{
		int ix = index * BYTES_PER_INT;
		return buffer.getInt(ix);
	}
	
	
	public void set(int index, int value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_INT;
		buffer.putInt(ix, value);
	}
}
