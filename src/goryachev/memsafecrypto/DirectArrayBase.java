// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import java.nio.ByteBuffer;


/**
 * Buffer for array classes backed by a DirectByteBuffer.
 */
public class DirectArrayBase
	implements ICryptoZeroable
{
	protected final ByteBuffer buffer;
	
	
	public DirectArrayBase(int capacity)
	{
		buffer = ByteBuffer.allocateDirect(capacity);
	}
	
	
	protected DirectArrayBase(DirectArrayBase src)
	{
		int sz = src.size();
		buffer = ByteBuffer.allocateDirect(sz);
		
		// copy without affecting the source buffer position
		for(int i=0; i<sz; i++)
		{
			byte v = src.buffer.get(i);
			buffer.put(i, v);
		}
	}

	
	public int size()
	{
		return buffer.capacity();
	}
	

	public void zero()
	{
		int sz = size();
		byte[] b = new byte[sz];
		buffer.put(b, 0, sz);
	}
}
