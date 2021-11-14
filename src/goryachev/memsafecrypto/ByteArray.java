// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.nio.ByteBuffer;


/**
 * DirectByteBuffer Wrapper.
 */
public final class ByteArray
	extends DirectArrayBase
{
	// TODO move to base?
	private boolean readonly;
	
	
	public ByteArray(int capacity)
	{
		super(capacity);
	}
	
	
	public ByteArray(ByteArray b)
	{
		super(b);
	}
	
	
	public void setReadOnly()
	{
		readonly = true;
	}

	
	public byte get(int ix)
	{
		return buffer.get(ix);
	}
	
	
	public void set(int ix, byte value)
	{
		if(readonly)
		{
			throw new Error("read-only");
		}
		
		buffer.put(ix, value);
	}
	
	
	public ByteArray readOnlyArray()
	{
		ByteArray b = new ByteArray(this);
		b.setReadOnly();
		return b;
	}
}
