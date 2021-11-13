package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.ICryptoZeroable;


public class KeyParameter
	implements CipherParameters, ICryptoZeroable
{
	private byte[] key;

	public KeyParameter(byte[] key)
	{
		this(key, 0, key.length);
	}


	public KeyParameter(byte[] key, int keyOff, int keyLen)
	{
		this.key = new byte[keyLen];

		System.arraycopy(key, keyOff, this.key, 0, keyLen);
	}


	public byte[] getKey()
	{
		return key;
	}
	
	
	public void zero()
	{
		// TODO
	}
}
