// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto.util;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.ICryptoZeroable;


/**
 * This class provides additional level of security by storing only the encrypted value in memory.
 * To avoid also keeping the key in memory, the key is generated each time from information
 * that stays constant during JVM session per hashCode() contract.
 */
public abstract class OpaqueMemObject
	implements ICryptoZeroable
{
	private CByteArray encrypted;
	
	
	protected OpaqueMemObject()
	{
	}
	
	
	protected OpaqueMemObject(OpaqueMemObject x)
	{
		encrypted = clone(x.encrypted);
	}
	
	
	protected OpaqueMemObject(CByteArray b)
	{
		setBytes(b);
	}
	
	
	protected OpaqueMemObject(CByteArray b, int offset, int len)
	{
		setBytes(b, offset, len);
	}
	
	
	protected CByteArray encrypted()
	{
		return encrypted;
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
				throw new RuntimeException("wrong type : " + x.getClass() + ", expecting " + getClass());
			}
		}
	}
	
	
	private static CByteArray clone(CByteArray b)
	{
		return (b == null) ? null : new CByteArray(b);
	}
	
	
	public final boolean isNull()
	{
		return (encrypted == null);
	}
	
	
	protected final void setBytes(CByteArray value)
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
	
	
	protected final void setBytes(CByteArray value, int off, int len)
	{
		CByteArray b = CByteArray.readOnly(value, off, len);
		try
		{
			try
			{
				encrypted = MemCrypt.encrypt(b);
			}
			catch(Exception e)
			{
				// should not happen
				throw new Error(e);
			}
		}
		finally
		{
			b.zero();
		}
	}
	
	
	public final String toString()
	{
		return String.valueOf('*');
	}
	
	
	/**
	 * Returns decrypted byte array representing the stored object.
	 */
	public final CByteArray getCByteArray()
	{
		if(encrypted == null)
		{
			return null;
		}
		else
		{
			try
			{
				CByteArray b = MemCrypt.decrypt(encrypted);
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
	
	
	public final void zero()
	{
		clear();
	}
}
