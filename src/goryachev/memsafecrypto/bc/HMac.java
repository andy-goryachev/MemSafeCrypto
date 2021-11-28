package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.util.CUtils;
import java.util.Hashtable;


/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
public class HMac
	implements Mac
{
	private final static byte IPAD = (byte)0x36;
	private final static byte OPAD = (byte)0x5C;

	private Digest digest;
	private int digestSize;
	private int blockLength;
	private Memoable ipadState;
	private Memoable opadState;
	private CByteArray inputPad;
	private CByteArray outputBuf;
	private static Hashtable<String,Integer> blockLengths;

	static
	{
		blockLengths = new Hashtable();

		blockLengths.put("GOST3411", Integer.valueOf(32));

		blockLengths.put("MD2", Integer.valueOf(16));
		blockLengths.put("MD4", Integer.valueOf(64));
		blockLengths.put("MD5", Integer.valueOf(64));

		blockLengths.put("RIPEMD128", Integer.valueOf(64));
		blockLengths.put("RIPEMD160", Integer.valueOf(64));

		blockLengths.put("SHA-1", Integer.valueOf(64));
		blockLengths.put("SHA-224", Integer.valueOf(64));
		blockLengths.put("SHA-256", Integer.valueOf(64));
		blockLengths.put("SHA-384", Integer.valueOf(128));
		blockLengths.put("SHA-512", Integer.valueOf(128));

		blockLengths.put("Tiger", Integer.valueOf(64));
		blockLengths.put("Whirlpool", Integer.valueOf(64));
	}


	/**
	 * Base constructor for one of the standard digest algorithms that the 
	 * byteLength of the algorithm is know for.
	 * 
	 * @param digest the digest.
	 */
	public HMac(Digest digest)
	{
		this(digest, getByteLength(digest));
	}


	private HMac(Digest digest, int byteLength)
	{
		this.digest = digest;
		this.digestSize = digest.getDigestSize();
		this.blockLength = byteLength;
		this.inputPad = new CByteArray(blockLength);
		this.outputBuf = new CByteArray(blockLength + digestSize);
	}
	
	
	private static int getByteLength(Digest digest)
	{
		if(digest instanceof ExtendedDigest)
		{
			return ((ExtendedDigest)digest).getByteLength();
		}

		Integer b = blockLengths.get(digest.getAlgorithmName());

		if(b == null)
		{
			throw new IllegalArgumentException("unknown digest passed: " + digest.getAlgorithmName());
		}

		return b.intValue();
	}


	public String getAlgorithmName()
	{
		return digest.getAlgorithmName() + "/HMAC";
	}


	public Digest getUnderlyingDigest()
	{
		return digest;
	}


	public void init(CipherParameters params)
	{
		digest.reset();

		// FIX zero
		CByteArray key = ((KeyParameter)params).getKey();
		int keyLength = key.length();

		if(keyLength > blockLength)
		{
			digest.update(key, 0, keyLength);
			digest.doFinal(inputPad, 0);

			keyLength = digestSize;
		}
		else
		{
			CUtils.arraycopy(key, 0, inputPad, 0, keyLength);
		}

		for(int i=keyLength; i<inputPad.length(); i++)
		{
			inputPad.set(i, (byte)0);
		}

		CUtils.arraycopy(inputPad, 0, outputBuf, 0, blockLength);

		xorPad(inputPad, blockLength, IPAD);
		xorPad(outputBuf, blockLength, OPAD);

		if(digest instanceof Memoable)
		{
			opadState = ((Memoable)digest).copy();

			((Digest)opadState).update(outputBuf, 0, blockLength);
		}

		digest.update(inputPad, 0, inputPad.length());

		if(digest instanceof Memoable)
		{
			ipadState = ((Memoable)digest).copy();
		}
	}


	public int getMacSize()
	{
		return digestSize;
	}


	public void update(byte in)
	{
		digest.update(in);
	}


	public void update(CByteArray in, int inOff, int len)
	{
		digest.update(in, inOff, len);
	}


	public int doFinal(CByteArray out, int outOff)
	{
		digest.doFinal(outputBuf, blockLength);

		if(opadState != null)
		{
			((Memoable)digest).reset(opadState);
			digest.update(outputBuf, blockLength, digest.getDigestSize());
		}
		else
		{
			digest.update(outputBuf, 0, outputBuf.length());
		}

		int len = digest.doFinal(out, outOff);

		for(int i=blockLength; i<outputBuf.length(); i++)
		{
			outputBuf.set(i, (byte)0);
		}

		if(ipadState != null)
		{
			((Memoable)digest).reset(ipadState);
		}
		else
		{
			digest.update(inputPad, 0, inputPad.length());
		}

		return len;
	}


	/**
	 * Reset the mac generator.
	 */
	public void reset()
	{
		/*
		 * reset the underlying digest.
		 */
		digest.reset();

		/*
		 * reinitialize the digest.
		 */
		digest.update(inputPad, 0, inputPad.length());
	}
	
	
	public void zero()
	{
		reset();
	}


	private static void xorPad(CByteArray pad, int len, byte n)
	{
		for(int i=0; i<len; ++i)
		{
			pad.xor(i, n);
		}
	}
}
