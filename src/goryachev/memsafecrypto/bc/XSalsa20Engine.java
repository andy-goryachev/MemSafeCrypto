package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CIntArray;
import goryachev.memsafecrypto.util.CUtils;


/**
 * Implementation of Daniel J. Bernstein's XSalsa20 stream cipher - Salsa20 with an extended nonce.
 * <p>
 * XSalsa20 requires a 256 bit key, and a 192 bit nonce.
 */
public class XSalsa20Engine
	extends Salsa20Engine
{
	public String getAlgorithmName()
	{
		return "XSalsa20";
	}


	protected int getNonceSize()
	{
		return 24;
	}


	/**
	 * XSalsa20 key generation: process 256 bit input key and 128 bits of the input nonce
	 * using a core Salsa20 function without input addition to produce 256 bit working key
	 * and use that with the remaining 64 bits of nonce to initialize a standard Salsa20 engine state.
	 */
	@Override
	protected void setKey(CByteArray keyBytes, CByteArray ivBytes)
	{
		if(keyBytes == null)
		{
			throw new IllegalArgumentException(getAlgorithmName() + " doesn't support re-init with null key");
		}

		if(keyBytes.length() != 32)
		{
			throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
		}

		// Set key for HSalsa20
		super.setKey(keyBytes, ivBytes);

		// Pack next 64 bits of IV into engine state instead of counter
		CUtils.littleEndianToInt(ivBytes, 8, engineState, 8, 2);

		// Process engine state to generate Salsa20 key
		CIntArray hsalsa20Out = new CIntArray(engineState.length());
		salsaCore(20, engineState, hsalsa20Out);

		// Set new key, removing addition in last round of salsaCore
		engineState.set(1, hsalsa20Out.get(0) - engineState.get(0));
		engineState.set(2, hsalsa20Out.get(5) - engineState.get(5));
		engineState.set(3, hsalsa20Out.get(10) - engineState.get(10));
		engineState.set(4, hsalsa20Out.get(15) - engineState.get(15));

		engineState.set(11, hsalsa20Out.get(6) - engineState.get(6));
		engineState.set(12, hsalsa20Out.get(7) - engineState.get(7));
		engineState.set(13, hsalsa20Out.get(8) - engineState.get(8));
		engineState.set(14, hsalsa20Out.get(9) - engineState.get(9));

		// Last 64 bits of input IV
		CUtils.littleEndianToInt(ivBytes, 16, engineState, 6, 2);
	}
}
