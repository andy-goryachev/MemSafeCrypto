// Copyright © 2011-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.CUtils;
import goryachev.memsafecrypto.util.OpaqueMemObject;


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
	
	
	public OpaqueChars(CCharArray cs)
	{
		set(cs);
	}
	
	
	public OpaqueChars(OpaqueChars op)
	{
		super(op);
	}
	
	
	public OpaqueChars()
	{
	}
	
	
	public void set(OpaqueChars x)
	{
		setFrom(x);
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
		if(cs == null)
		{
			clear();
		}
		else
		{
			CCharArray a = new CCharArray(cs);
			try
			{
				set(a);		
			}
			finally
			{
				a.zero();
			}
		}
	}
	
	
	public final void set(CCharArray cs)
	{
		CByteArray b = CUtils.charsToBytes(cs);
		try
		{
			setBytes(b);
		}
		finally
		{
			Crypto.zero(b);
		}
	}
	
	
	public final CCharArray getChars()
	{
		CByteArray b = getCByteArray();
		try
		{
			return CUtils.bytesToChars(b);
		}
		finally
		{
			Crypto.zero(b);
		}
	}
	
	
	public boolean sameContentAs(OpaqueChars cs)
	{
		if(cs == null)
		{
			return false;
		}
		
		CByteArray a = getCByteArray();
		try
		{
			CByteArray b = cs.getCByteArray();
			try
			{
				if(a == null)
				{
					return (b == null);
				}
				else
				{
					if(b == null)
					{
						return false;
					}
					return a.sameContentAs(b);
				}
			}
			finally
			{
				Crypto.zero(b);
			}
		}
		finally
		{
			Crypto.zero(a);
		}
	}


	public void append(String s)
	{
		if(s != null)
		{
			CCharArray a = getChars();
			try
			{
				char[] cs = s.toCharArray();
				try
				{
					CCharArray b;
					if(a == null)
					{
						b = new CCharArray(cs);
					}
					else
					{
						b = a.append(cs);
					}
					set(b);
					b.zero();
				}
				finally
				{
					Crypto.zero(cs);
				}
			}
			finally
			{
				Crypto.zero(a);
			}
		}
	}
	
	
	public void append(char ch)
	{
		CCharArray a = getChars();
		try
		{
			CCharArray b;
			if(a == null)
			{
				b = new CCharArray(new char[] { ch });
			}
			else
			{
				b = a.append(new char[] { ch });
			}
			set(b);
			b.zero();
		}
		finally
		{
			Crypto.zero(a);
		}
	}


	public void deleteLastChar()
	{
		CCharArray a = getChars();
		try
		{
			if(a == null)
			{
				return;
			}
			
			CCharArray b = a.deleteLastChar();
			set(b);
			b.zero();
		}
		finally
		{
			Crypto.zero(a);
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
