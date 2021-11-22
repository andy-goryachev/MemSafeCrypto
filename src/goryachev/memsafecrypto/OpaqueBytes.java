// Copyright © 2012-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.memsafecrypto.util.OpaqueMemObject;


/**
 * This class provides an opaque storage for a byte array.
 */
public final class OpaqueBytes
	extends OpaqueMemObject
{
	public OpaqueBytes(CByteArray b)
	{
		super(b);
	}
	
	
	public OpaqueBytes()
	{
	}
	
	
	public final CByteArray getValue()
	{
		return getCBytesArray();
	}
	
	
	@Deprecated /** use setValue(CByteArray b) */
	public final void setValue(byte[] b)
	{
		CByteArray a = (b == null) ? null : CByteArray.readOnly(b); 
		setBytes(a);
	}
	
	
	public final void setValue(CByteArray b)
	{
		setBytes(b);
	}
	
	
	public final void setValue(OpaqueBytes b)
	{
		setFrom(b);
	}
}
