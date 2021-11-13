// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.common.util.D;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;


/**
 * TestBuffer.
 */
public class TestBuffer
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void t()
	{
		int size = 16;
		
		for(int i=0; i<10; i++)
		{
			ByteBuffer b = ByteBuffer.allocateDirect(size);
			D.print(i, b);
		}
	}
}
