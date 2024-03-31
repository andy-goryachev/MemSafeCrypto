// Copyright © 2013-2024 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;


public interface AKey
{
	/** Converts the key to a byte array representation */
	public byte[] toByteArray() throws Exception;
	
	
	/** Returns underlying object */
	public Object getKey();
	

	/** Irrevocably destroys underlying key material, if supported */ 
	public void destroy();
}
