package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.ICryptoZeroable;


public class KeyParameter
	implements CipherParameters, ICryptoZeroable
{
	private final CByteArray key;
	

	public KeyParameter(byte[] key)
	{
		this(key, 0, key.length);
	}


	public KeyParameter(byte[] key, int keyOff, int keyLen)
	{
		this.key = CByteArray.readOnly(key, keyOff, keyLen); 
	}
	
	
	public KeyParameter(CByteArray key)
	{
		this.key = key.toReadOnly();
	}
	
	
	public KeyParameter(CByteArray key, int keyOff, int keyLen)
	{
		this.key = key.toReadOnly(keyOff, keyLen);
	}


	public CByteArray getKey()
	{
		return key;
	}
	
	
	public void zero()
	{
		key.zero();
	}
}
