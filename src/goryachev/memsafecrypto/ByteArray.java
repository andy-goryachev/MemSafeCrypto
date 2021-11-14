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
	
	
	public int length()
	{
		return sizeInBytes();
	}
	
	
	public void setReadOnly()
	{
		readonly = true;
	}

	
	public byte get(int index)
	{
		return buffer.get(index);
	}
	
	
	public void set(int index, byte value)
	{
		if(readonly)
		{
			throw new Error("read-only");
		}
		
		buffer.put(index, value);
	}
	
	
	public void set(int index, byte[] src, int offset, int len)
	{
		if(readonly)
		{
			throw new Error("read-only");
		}
		
		buffer.position(index);
		buffer.put(src, offset, len);
	}
	
	
	public ByteArray toReadOnly()
	{
		ByteArray b = new ByteArray(this);
		b.setReadOnly();
		return b;
	}
	
	
	public ByteArray toReadOnly(int offset, int length)
	{
		ByteArray b = new ByteArray(length);
		b.copyBytes(0, this, offset, length);
		b.setReadOnly();
		return b;
	}
	
	
	public static ByteArray readOnly(byte[] src)
	{
		return readOnly(src, 0, src.length);
	}
	
	
	public static ByteArray readOnly(byte[] src, int offset, int len)
	{
		ByteArray b = new ByteArray(len);
		b.set(0, src, offset, len);
		b.setReadOnly();
		return b;
	}
}
