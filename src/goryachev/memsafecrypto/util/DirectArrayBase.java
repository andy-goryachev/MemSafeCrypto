// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.ICryptoZeroable;
import java.nio.ByteBuffer;


/**
 * Buffer for array classes backed by a DirectByteBuffer.
 */
public class DirectArrayBase
	implements ICryptoZeroable
{
	protected final ByteBuffer buffer;
	private boolean readonly;

	
	public DirectArrayBase(int capacity)
	{
		buffer = ByteBuffer.allocateDirect(capacity);
	}
	
	
	protected DirectArrayBase(DirectArrayBase src)
	{
		this(src, 0, src.sizeInBytes());
	}
	
	
	protected DirectArrayBase(DirectArrayBase src, int offset, int length)
	{
		buffer = ByteBuffer.allocateDirect(length);
		
		// copy without affecting the source buffer position
		for(int i=0; i<length; i++)
		{
			byte v = src.buffer.get(i + offset);
			buffer.put(i, v);
		}
	}
	
	
	public void setReadOnly()
	{
		readonly = true;
	}


	protected void copyBytes(int index, DirectArrayBase src, int srcOffset, int srcLength)
	{
		// TODO validate input
		
		for(int i=0; i<srcLength; i++)
		{
			byte v = src.buffer.get(srcOffset + i);
			buffer.put(index + i, v);
		}
	}

	
	protected int sizeInBytes()
	{
		return buffer.capacity();
	}
	
	
	public int position()
	{
		return buffer.position();
	}
	
	
	protected void checkWriteable()
	{
		if(readonly)
		{
			throw new UnsupportedOperationException("this buffer is read-only");
		}
	}
	

	public void zero()
	{
		int sz = sizeInBytes();
		byte zero = (byte)0;
		for(int i=0; i<sz; i++)
		{
			buffer.put(i, zero);
		}
	}
}
