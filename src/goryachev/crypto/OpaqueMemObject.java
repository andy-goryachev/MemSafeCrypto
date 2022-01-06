// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;

/**
 * This class provides additional level of security by storing only the encrypted value in memory.
 * To avoid also keeping the key in memory, the key is generated each time from information
 * that stays constant during JVM session per hashCode() contract.
 */
abstract class OpaqueMemObject
{
	private byte[] encrypted;
	
	
	protected OpaqueMemObject()
	{
	}
	
	
	protected OpaqueMemObject(OpaqueMemObject x)
	{
		encrypted = clone(x.encrypted);
	}
	
	
	protected OpaqueMemObject(byte[] b)
	{
		setBytes(b);
	}
	
	
	protected void setFrom(OpaqueMemObject x)
	{
		if(x == null)
		{
			encrypted = null;
		}
		else
		{
			if(x.getClass() == getClass())
			{
				encrypted = clone(x.encrypted);
			}
			else
			{
				encrypted = null;
			}
		}
	}
	
	
	private static byte[] clone(byte[] b)
	{
		return (b == null) ? null : b.clone();
	}
	
	
	public final boolean isNull()
	{
		return (encrypted == null);
	}
	
	
	protected final void setBytes(byte[] value)
	{
		if(value == null)
		{
			encrypted = null;
		}
		else
		{
			try
			{
				encrypted = MemCrypt.encrypt(value);
			}
			catch(Exception e)
			{
				// should not happen
				throw new Error(e);
			}
		}
	}
	
	
	protected final void setBytes(byte[] value, int off, int len)
	{
		byte[] v = new byte[len];
		try
		{
			System.arraycopy(value, off, v, 0, len);
			
			try
			{
				encrypted = MemCrypt.encrypt(value);
			}
			catch(Exception e)
			{
				// should not happen
				throw new Error(e);
			}
		}
		finally
		{
			Crypto.zero(v);
		}
	}
	
	
	public final String toString()
	{
		return String.valueOf('*');
	}
	
	
	/**
	 * Returns decrypted byte array representing the stored object.
	 */
	public final byte[] getBytes()
	{
		if(encrypted == null)
		{
			return null;
		}
		else
		{
			try
			{
				byte[] b = MemCrypt.decrypt(encrypted);
				return b;
			}
			catch(Exception e)
			{
				// should not happen
				throw new Error(e);
			}
		}
	}
	
	
	public boolean isEmpty()
	{
		return encrypted == null;
	}
	
	
	public final void clear()
	{
		Crypto.zero(encrypted);
		encrypted = null;
	}
}
