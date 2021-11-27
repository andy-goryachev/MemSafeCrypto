// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.memsafecrypto.bc.salsa.TestMemCrypt;
import goryachev.memsafecrypto.bc.salsa.TestXSalsa20Poly1305Streams;
import goryachev.memsafecrypto.bc.salsa.TestXSalsa20Streams;


/**
 * Test All.
 */
public class TestAll
{
	public static void main(String[] args)
	{
		TF.run
		(
			TestBlake2b.class,
			TestCCharArray.class,
			TestXSalsa20Poly1305Streams.class,
			TestXSalsa20Streams.class,
			TestMemCrypt.class
		);
	}
}
