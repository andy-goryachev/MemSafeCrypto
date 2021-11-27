package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.util.CUtils;


/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
public abstract class GeneralDigest
	implements ExtendedDigest, Memoable
{
	protected abstract void processWord(byte[] in, int inOff);
	
	protected abstract void processWord(CByteArray in, int inOff);

	protected abstract void processLength(long bitLength);

	protected abstract void processBlock();
	
	//
	
	private static final int BYTE_LENGTH = 64;

	private final CByteArray xBuf = new CByteArray(4);
	private int xBufOff;
	private long byteCount;

	
	/**
	 * Standard constructor
	 */
	protected GeneralDigest()
	{
		xBufOff = 0;
	}


	/**
	 * Copy constructor.  We are using copy constructors in place
	 * of the Object.clone() interface as this interface is not
	 * supported by J2ME.
	 */
	protected GeneralDigest(GeneralDigest t)
	{
		copyIn(t);
	}


	protected GeneralDigest(CByteArray encodedState)
	{
		CUtils.arraycopy(encodedState, 0, xBuf, 0, xBuf.length());
		xBufOff = CUtils.bigEndianToInt(encodedState, 4);
		byteCount = CUtils.bigEndianToLong(encodedState, 8);
	}


	protected void copyIn(GeneralDigest t)
	{
		CUtils.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length());

		xBufOff = t.xBufOff;
		byteCount = t.byteCount;
	}


	public void update(byte in)
	{
		xBuf.set(xBufOff++, in);

		if(xBufOff == xBuf.length())
		{
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}


	public void update(byte[] in, int inOff, int len)
	{
		len = Math.max(0, len);

		// fill the current word
		int i = 0;
		if(xBufOff != 0)
		{
			while(i < len)
			{
				xBuf.set(xBufOff++, in[inOff + i++]);
				if(xBufOff == 4)
				{
					processWord(xBuf, 0);
					xBufOff = 0;
					break;
				}
			}
		}

		// process whole words.
		int limit = ((len - i) & ~3) + i;
		for(; i < limit; i += 4)
		{
			processWord(in, inOff + i);
		}

		// load in the remainder.
		while(i < len)
		{
			xBuf.set(xBufOff++, in[inOff + i++]);
		}

		byteCount += len;
	}
	
	
	public void update(CByteArray in, int inOff, int len)
	{
		len = Math.max(0, len);

		// fill the current word
		int i = 0;
		if(xBufOff != 0)
		{
			while(i < len)
			{
				xBuf.set(xBufOff++, in.get(inOff + i++));
				if(xBufOff == 4)
				{
					processWord(xBuf, 0);
					xBufOff = 0;
					break;
				}
			}
		}

		// process whole words.
		int limit = ((len - i) & ~3) + i;
		for(; i < limit; i += 4)
		{
			processWord(in, inOff + i);
		}

		// load in the remainder.
		while(i < len)
		{
			xBuf.set(xBufOff++, in.get(inOff + i++));
		}

		byteCount += len;
	}


	public void finish()
	{
		long bitLength = (byteCount << 3);

		//
		// add the pad bytes.
		//
		update((byte)128);

		while(xBufOff != 0)
		{
			update((byte)0);
		}

		processLength(bitLength);

		processBlock();
	}


	public void reset()
	{
		byteCount = 0;
		xBufOff = 0;
		
		for(int i=0; i<xBuf.length(); i++)
		{
			xBuf.set(i, (byte)0);
		}
	}


	protected void populateState(CByteArray state)
	{
		CUtils.arraycopy(xBuf, 0, state, 0, xBufOff);
		CUtils.intToBigEndian(xBufOff, state, 4);
		CUtils.longToBigEndian(byteCount, state, 8);
	}


	public int getByteLength()
	{
		return BYTE_LENGTH;
	}
}
