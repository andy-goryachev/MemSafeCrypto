// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.eax;
import goryachev.crypto.Crypto;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;


/** 
 * Simple utility for encrypion of small byte arrays using AES cipher in EAX mode.
 */ 
public final class EAXCipher
{
	private static final int MAC_SIZE_BITS = 64;
	private static final byte[] ZERO_BYTE_ARRAY = new byte[0];

	
	public static final byte[] encrypt(byte[] key, byte[] nonce, byte[] data) throws Exception
	{
		EAXBlockCipher cipher = new EAXBlockCipher(new AESEngine());
		KeyParameter kp = new KeyParameter(key);

		try
		{
			AEADParameters par = new AEADParameters(kp, MAC_SIZE_BITS, nonce, ZERO_BYTE_ARRAY);
			cipher.init(true, par);
			
			int sz = cipher.getOutputSize(data.length);
			byte[] out = new byte[sz];

			int off = cipher.processBytes(data, 0, data.length, out, 0);
			cipher.doFinal(out, off);
			return out;
		}
		finally
		{
			Crypto.zero(kp);
			Crypto.zero(key);
		}
	}
	

	public static final byte[] decrypt(byte[] key, byte[] nonce, byte[] data) throws Exception
	{
		EAXBlockCipher cipher = new EAXBlockCipher(new AESEngine());
		KeyParameter kp = new KeyParameter(key);
		
		try
		{
			AEADParameters par = new AEADParameters(kp, MAC_SIZE_BITS, nonce, ZERO_BYTE_ARRAY);
			cipher.init(false, par);
			
			int sz = cipher.getOutputSize(data.length);
			byte[] out = new byte[sz];
			
			int off = cipher.processBytes(data, 0, data.length, out, 0);
			cipher.doFinal(out, off);
			return out;
		}
		finally
		{
			Crypto.zero(kp);
			Crypto.zero(key);
		}
	}
}
