// Copyright © 2013-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;


public class ASecretKey
	implements AKey
{
	private final byte[] key;
	
	
	public ASecretKey(byte[] key)
	{
		this.key = key.clone();
	}
	
	
	public byte[] toByteArray() throws Exception
	{
		return key.clone();
	}
	
	
	public Object getKey()
	{
		return this;
	}


	public void destroy()
	{
		Crypto.zero(key);
	}
}
