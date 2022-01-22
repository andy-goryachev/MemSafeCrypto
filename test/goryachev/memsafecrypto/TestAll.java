// Copyright © 2021-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.memsafecrypto.bc.TestArgon2;
import goryachev.memsafecrypto.bc.TestScrypt;
import goryachev.memsafecrypto.bc.salsa.TestXSalsa20Poly1305Streams;
import goryachev.memsafecrypto.bc.salsa.TestXSalsaTools;
import goryachev.memsafecrypto.salsa.TestXSalsaRandomAccessFile;
import goryachev.memsafecrypto.util.TestMemCrypt;


/**
 * Test All.
 */
public class TestAll
{
	public static void main(String[] args)
	{
		TF.run
		(
			TestArgon2.class,
			TestBlake2b.class,
			TestCByteArrayOutputStream.class,
			TestCCharArray.class,
			TestMemCrypt.class,
			TestScrypt.class,
			TestXSalsa20Poly1305Streams.class,
			TestXSalsaRandomAccessFile.class,
			TestXSalsaTools.class
		);
	}
}
