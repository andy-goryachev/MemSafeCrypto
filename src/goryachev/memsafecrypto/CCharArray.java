// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable char[] equivalent based on DirectByteBuffer.
 */
public class CCharArray
	extends DirectArrayBase
{
	public static final int BYTES_PER_CHAR = 2;
	
	
	public CCharArray(int capacity)
	{
		super(capacity * BYTES_PER_CHAR);
	}
	
	
	public CCharArray(CCharArray x)
	{
		super(x);
	}
	
	
	public CCharArray(char[] cs)
	{
		this(cs.length);
		
		for(int i=0; i<cs.length; i++)
		{
			char c = cs[i];
			buffer.putChar(i * BYTES_PER_CHAR, c);
		}
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
	
	
	public char[] toCharArray()
	{
		int len = length();
		char[] rv = new char[len];
		for(int i=0; i<len; i++)
		{
			rv[i] = get(i);
		}
		return rv;
	}


	public CCharArray append(char[] cs)
	{
		int len = length();
		CCharArray rv = new CCharArray(len + cs.length);
		
		for(int i=0; i<len; i++)
		{
			char c = get(i);
			rv.set(i, c);
		}
		
		for(int i=0; i<cs.length; i++)
		{
			char c = cs[i];
			rv.set(i + len, c);
		}
		
		return rv;
	}


	public CCharArray deleteLastChar()
	{
		int len = length();
		if(len <= 1)
		{
			return new CCharArray(0);
		}
		
		len--;
		
		CCharArray rv = new CCharArray(len);
		for(int i=0; i<len; i++)
		{
			char c = get(i);
			rv.set(i, c);
		}
		
		return rv;
	}
	
	
	public boolean sameContentAs(CCharArray a)
	{
		if(a == null)
		{
			return false;
		}
		
		int sz = length();
		if(sz != a.length())
		{
			return false;
		}
		
		for(int i=0; i<sz; i++)
		{
			char c = get(i);
			if(c != a.get(i))
			{
				return false;
			}
		}
		return true;
	}
}
