// Copyright © 2012-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.bc.salsa;
import goryachev.common.test.TF;
import goryachev.common.test.Test;
import goryachev.memsafecrypto.MemCrypt;
import java.util.Random;


// tests reversibility of MemCrypt in-memory encryption
public class TestMemCrypt
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void test() throws Exception
	{
		int maxLen = 2;
		
		Random r = new Random();
		for(int i=0; i<1000; i++)
		{
			TF.print(i);
			
			int len = r.nextInt(maxLen);
			byte[] b = new byte[len];
			r.nextBytes(b);
			
			t(b);
		}
	}
	
	
	protected void t(byte[] b) throws Exception
	{
		byte[] en = MemCrypt.encrypt(b);
		byte[] de = MemCrypt.decrypt(en);
		TF.eq(de, b);
		TF.list(b);
		TF.list(de);
	}
}
