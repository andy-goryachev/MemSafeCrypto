package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;


/**
 * base interface for general purpose byte derivation functions.
 */
public interface DerivationFunction
{
	public void init(DerivationParameters param);


	public int generateBytes(CByteArray out, int outOff, int len) throws DataLengthException, IllegalArgumentException;
}
