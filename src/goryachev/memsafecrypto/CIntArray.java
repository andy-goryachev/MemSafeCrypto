// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable int[] equivalent based on DirectByteBuffer.
 */
public class CIntArray
	extends DirectArrayBase
{
	private static final int BYTES_PER_INT = 4;
	
	
	public CIntArray(int capacity)
	{
		super(capacity * BYTES_PER_INT);
	}
	
	
	public CIntArray(CIntArray x)
	{
		super(x);
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
	
	
	public void fill(int value)
	{
		checkWriteable();
		
		int len = length();
		for(int i=0; i<len; i++)
		{
			int ix = i * BYTES_PER_INT;
			buffer.putInt(ix, value);
		}
	}


	public void copy(int toOffset, int[] src, int srcOffset, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			int v = src[i + srcOffset];
			int ix = (i + toOffset) * BYTES_PER_INT;
			buffer.putInt(ix, v);
		}
	}
	
	
	public int[] toArray()
	{
		int len = length();
		int[] rv = new int[len];
		for(int i=0; i<len; i++)
		{
			rv[i] = get(i);
		}
		return rv;
	}
}
