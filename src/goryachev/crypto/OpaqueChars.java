// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import goryachev.common.util.CKit;


/**
 * This class provides an opaque storage for a char array.
 */
public final class OpaqueChars
	extends OpaqueMemObject
{
	public OpaqueChars(char[] cs)
	{
		set(cs);
	}
	
	
	public OpaqueChars(OpaqueChars op)
	{
		super(op);
	}
	
	
	public OpaqueChars(byte[] b)
	{
		super(b);
	}
	
	
	public OpaqueChars()
	{
	}
	
	
	public void set(OpaqueChars x)
	{
		char[] cs = null;
		try
		{
			if(x != null)
			{
				cs = x.getChars();
			}
			
			set(cs);
		}
		finally
		{
			Crypto.zero(cs);
		}
	}
	
	
	public void set(String s)
	{
		char[] cs = null;
		try
		{
			if(s != null)
			{
				cs = s.toCharArray();
			}
			
			set(cs);
		}
		finally
		{
			Crypto.zero(cs);
		}
	}
	
	
	public final void set(char[] cs)
	{
		byte[] b = Crypto.chars2bytes(cs);
		try
		{
			setBytes(b);
		}
		finally
		{
			Crypto.zero(b);
		}
	}
	
	
	public final char[] getChars()
	{
		byte[] b = getBytes();
		try
		{
			return Crypto.bytes2chars(b);
		}
		finally
		{
			Crypto.zero(b);
		}
	}
	
	
	public boolean sameAs(OpaqueChars cs)
	{
		if(cs == null)
		{
			return false;
		}
		
		byte[] me = getBytes();
		try
		{
			byte[] him = cs.getBytes();
			try
			{
				return CKit.equals(me, him);
			}
			finally
			{
				Crypto.zero(him);
			}
		}
		finally
		{
			Crypto.zero(me);
		}
	}


	public void append(String s)
	{
		if(s != null)
		{
			append(s.toCharArray());
		}
	}
	
	
	public void append(char[] add)
	{
		char[] cs = getChars();
		try
		{
			int len = cs == null ? 0 : cs.length;
			char[] rv = new char[len + add.length];
			try
			{
				if(cs != null)
				{
					System.arraycopy(cs, 0, rv, 0, cs.length);
				}
				System.arraycopy(add, 0, rv, len, add.length);
				set(rv);
			}
			finally
			{
				Crypto.zero(rv);
			}
		}
		finally
		{
			Crypto.zero(cs);
		}
	}


	public void deleteLastChar()
	{
		char[] cs = getChars();
		try
		{
			int len = cs.length - 1;
			if(len >= 0)
			{
				// TODO this does not handle surrogate characters
				char[] rv = new char[len];
				try
				{
					System.arraycopy(cs, 0, rv, 0, len);
					set(rv);
				}
				finally
				{
					Crypto.zero(rv);
				}
			}
			
		}
		finally
		{
			Crypto.zero(cs);
		}
	}
	
	
	public OpaqueChars copy()
	{
		return new OpaqueChars(this);
	}
	
	
	public static OpaqueChars copy(OpaqueChars x)
	{
		if(x == null)
		{
			return null;
		}
		else
		{
			return x.copy();
		}
	}
}
