// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable char[] equivalent based on DirectByteBuffer.
 */
public class CCharArray
	extends DirectArrayBase
{
	private static final int BYTES_PER_CHAR = 2;
	
	
	public CCharArray(int capacity)
	{
		super(capacity * BYTES_PER_CHAR);
	}
	
	
	public CCharArray(CCharArray x)
	{
		super(x);
	}
	
	
	public int length()
	{
		return sizeInBytes() / BYTES_PER_CHAR;
	}

	
	public char get(int index)
	{
		int ix = index * BYTES_PER_CHAR;
		return buffer.getChar(ix);
	}
	
	
	public void set(int index, char value)
	{
		checkWriteable();
		
		int ix = index * BYTES_PER_CHAR;
		buffer.putChar(ix, value);
	}
	
	
	public void fill(char value)
	{
		checkWriteable();
		
		int len = length();
		for(int i=0; i<len; i++)
		{
			int ix = i * BYTES_PER_CHAR;
			buffer.putChar(ix, value);
		}
	}


	public void copy(int toOffset, char[] src, int srcOffset, int length)
	{
		checkWriteable();
		
		for(int i=0; i<length; i++)
		{
			char v = src[i + srcOffset];
			int ix = (i + toOffset) * BYTES_PER_CHAR;
			buffer.putChar(ix, v);
		}
	}
	
	
	public char[] toArray()
	{
		int len = length();
		char[] rv = new char[len];
		for(int i=0; i<len; i++)
		{
			rv[i] = get(i);
		}
		return rv;
	}
}
