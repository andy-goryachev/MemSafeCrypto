// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto.digest;
import goryachev.common.util.api.IMessageDigestBlake2b;
import org.bouncycastle.crypto.digests.Blake2bDigest;


/**
 * CDigest based on Blake2bMessageDigest.
 */
public class CDigestBlake2b
	implements IMessageDigestBlake2b
{
	private final Blake2bDigest md;
	
	
	public CDigestBlake2b(int bits)
	{
		md = new Blake2bDigest(bits);
	}
	
	
	public void update(byte[] buf, int offset, int length)
	{
		md.update(buf, offset, length);
	}
	
	
	public void update(byte b)
	{
		md.update(b);
	}
	
	
	public void reset()
	{
		md.reset();
	}
	
	
	public byte[] digest()
	{
		int len = md.getDigestSize();
		byte[] b = new byte[len];
		md.doFinal(b, 0);
		return b;
	}
}
