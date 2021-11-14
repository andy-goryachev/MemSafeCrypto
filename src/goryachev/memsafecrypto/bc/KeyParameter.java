package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.ByteArray;
import goryachev.memsafecrypto.ICryptoZeroable;


public class KeyParameter
	implements CipherParameters, ICryptoZeroable
{
	private final ByteArray key;
	

	public KeyParameter(byte[] key)
	{
		this(key, 0, key.length);
	}


	public KeyParameter(byte[] key, int keyOff, int keyLen)
	{
		this.key = ByteArray.readOnly(key, keyOff, keyLen); 
	}
	
	
	public KeyParameter(ByteArray key)
	{
		this.key = key.toReadOnly();
	}
	
	
	public KeyParameter(ByteArray key, int keyOff, int keyLen)
	{
		this.key = key.toReadOnly(keyOff, keyLen);
	}


	public ByteArray getKey()
	{
		return key;
	}
	
	
	public void zero()
	{
		key.zero();
	}
}
