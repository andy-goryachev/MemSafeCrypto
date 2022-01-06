// Copyright © 2013-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;


/** Private key wrapper. */
public class APrivateKey
	implements AKey
{
	private Object key;
	
	
	public APrivateKey(RSAPrivateCrtKeyParameters key)
	{
		this.key = key;
	}
	
	
	public byte[] toByteArray() throws Exception
	{
		return Crypto.toByteArray(key);
	}
	
	
	public Object getKey()
	{
		return key;
	}
	
	
	public void destroy()
	{
		key = null;
	}
}
