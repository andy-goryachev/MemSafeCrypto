// Copyright © 2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.DirectArrayBase;


/**
 * Zeroable int[][] equivalent based on DirectByteBuffer.
 */
public class CIntArrayArray
	extends DirectArrayBase
{
	public static final int BYTES_PER_INT = 4;
	private final int width;
	
	
	public CIntArrayArray(int height, int width)
	{
		super(height * width * BYTES_PER_INT);
		this.width = width;
	}
	
	
	public void set(int x, int y, int value)
	{
		int ix = (x + (y * width)) * BYTES_PER_INT;
		buffer.putInt(ix, value);
	}
	
	
	public int get(int x, int y)
	{
		int ix = (x + (y * width)) * BYTES_PER_INT;
		return buffer.getInt(ix);
	}
}
