// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.memsafecrypto.util.CByteArrayOutputStream;
import java.util.Random;


/**
 * Tests CByteArrayOutputStream.
 */
public class TestCByteArrayOutputStream
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void test() throws Exception
	{
		Random r = new Random();
		
		t(r, CByteArrayOutputStream.MAX_SIZE);
		
		for(int i=0; i<32; i++)
		{
			long size = (1L << i);
			for(int j=-3; j<3; j++)
			{
				long sz = size + j;
				if(sz < 0)
				{
					continue;
				}
				else if(sz > CByteArrayOutputStream.MAX_SIZE)
				{
					return;
				}
				
				t(r, (int)sz);
			}
		}
	}
	
	
	protected void t(Random r, int len) throws Exception
	{
		TF.print(len);
		
		byte[] src = new byte[len];
		r.nextBytes(src);
		
		CByteArrayOutputStream out = new CByteArrayOutputStream(r.nextInt(len + 1));
		out.write(src);
		CByteArray ba = out.toCByteArray();
		byte[] res = ba.toByteArray();
		
		TF.eq(res, src);
	}
}
