package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.ICryptoZeroable;
import goryachev.memsafecrypto.util.CUtils;
import goryachev.memsafecrypto.CIntArray;


/**
 * Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
 */
public class Salsa20Engine
	implements SkippingStreamCipher, ICryptoZeroable
{
	public final static int DEFAULT_ROUNDS = 20;

	/** Constants */
	private final static int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes

	private final static int[] TAU_SIGMA = CUtils.littleEndianToInt(CUtils.toByteArray("expand 16-byte k" + "expand 32-byte k"), 0, 8);

	protected int rounds;

	/*
	 * variables to hold the state of the engine
	 * during encryption and decryption
	 */
	private int index = 0;
	protected CIntArray engineState = new CIntArray(STATE_SIZE); // state
	protected CIntArray x = new CIntArray(STATE_SIZE); // internal buffer
	private CByteArray keyStream = new CByteArray(STATE_SIZE * 4); // expanded state, 64 bytes
	private boolean initialised = false;

	/*
	 * internal counter
	 */
	private int cW0, cW1, cW2;
	

	/**
	 * Creates a 20 round Salsa20 engine.
	 */
	public Salsa20Engine()
	{
		this(DEFAULT_ROUNDS);
	}


	/**
	 * Creates a Salsa20 engine with a specific number of rounds.
	 * @param rounds the number of rounds (must be an even number).
	 */
	public Salsa20Engine(int rounds)
	{
		if(rounds <= 0 || (rounds & 1) != 0)
		{
			throw new IllegalArgumentException("'rounds' must be a positive, even number");
		}

		this.rounds = rounds;
	}


	/**
	 * initialise a Salsa20 cipher.
	 *
	 * @param forEncryption whether or not we are for encryption.
	 * @param params the parameters required to set up the cipher.
	 * @exception IllegalArgumentException if the params argument is
	 * inappropriate.
	 */
	public void init(boolean forEncryption, CipherParameters params)
	{
		/* 
		* Salsa20 encryption and decryption is completely
		* symmetrical, so the 'forEncryption' is 
		* irrelevant. (Like 90% of stream ciphers)
		*/

		if(!(params instanceof ParametersWithIV))
		{
			throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must include an IV");
		}

		ParametersWithIV ivParams = (ParametersWithIV)params;

		CByteArray iv = ivParams.getIV();
		if(iv == null || iv.length() != getNonceSize())
		{
			throw new IllegalArgumentException(getAlgorithmName() + " requires exactly " + getNonceSize() + " bytes of IV");
		}

		CipherParameters keyParam = ivParams.getParameters();
		if(keyParam == null)
		{
			if(!initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " KeyParameter can not be null for first initialisation");
			}

			setKey(null, iv);
		}
		else if(keyParam instanceof KeyParameter)
		{
			setKey(((KeyParameter)keyParam).getKey(), iv);
		}
		else
		{
			throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must contain a KeyParameter (or null for re-init)");
		}

		reset();

		initialised = true;
	}


	protected int getNonceSize()
	{
		return 8;
	}


	public String getAlgorithmName()
	{
		String name = "Salsa20";
		if(rounds != DEFAULT_ROUNDS)
		{
			name += "/" + rounds;
		}
		return name;
	}


	public byte returnByte(byte in)
	{
		if(limitExceeded())
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
		}

		byte out = (byte)(keyStream.get(index) ^ in);
		index = (index + 1) & 63;

		if(index == 0)
		{
			advanceCounter();
			generateKeyStream(keyStream);
		}

		return out;
	}


	protected void advanceCounter(long diff)
	{
		int hi = (int)(diff >>> 32);
		int lo = (int)diff;

		if(hi > 0)
		{
			engineState.add(9, hi);
		}

		int oldState = engineState.get(8);

		engineState.add(8, lo);

		if(oldState != 0 && engineState.get(8) < oldState)
		{
			engineState.increment(9);
		}
	}


	protected void advanceCounter()
	{
		if(engineState.incrementAndGet(8) == 0)
		{
			engineState.increment(9);
		}
	}


	protected void retreatCounter(long diff)
	{
		int hi = (int)(diff >>> 32);
		int lo = (int)diff;

		if(hi != 0)
		{
			if((engineState.get(9) & 0xffffffffL) >= (hi & 0xffffffffL))
			{
				engineState.subtract(9, hi);
			}
			else
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}
		}

		if((engineState.get(8) & 0xffffffffL) >= (lo & 0xffffffffL))
		{
			engineState.subtract(8, lo);
		}
		else
		{
			if(engineState.get(9) != 0)
			{
				engineState.decrement(9);
				engineState.subtract(8, lo);
			}
			else
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}
		}
	}


	protected void retreatCounter()
	{
		if(engineState.get(8) == 0 && engineState.get(9) == 0)
		{
			throw new IllegalStateException("attempt to reduce counter past zero.");
		}

		if(engineState.decrementAndGet(8) == -1)
		{
			engineState.decrement(9);
		}
	}
	
	
	public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
	{
		if(!initialised)
		{
			throw new IllegalStateException(getAlgorithmName() + " not initialised");
		}

		if((inOff + len) > in.length)
		{
			throw new DataLengthException("input buffer too short");
		}

		if((outOff + len) > out.length)
		{
			throw new OutputLengthException("output buffer too short");
		}

		if(limitExceeded(len))
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
		}

		for(int i=0; i<len; i++)
		{
			out[i + outOff] = (byte)(keyStream.get(index) ^ in[i + inOff]);
			index = (index + 1) & 63;

			if(index == 0)
			{
				advanceCounter();
				generateKeyStream(keyStream);
			}
		}

		return len;
	}
	
	
	public int processBytes(byte[] in, int inOff, int len, CByteArray out, int outOff)
	{
		if(!initialised)
		{
			throw new IllegalStateException(getAlgorithmName() + " not initialised");
		}

		if((inOff + len) > in.length)
		{
			throw new DataLengthException("input buffer too short");
		}

		if((outOff + len) > out.length())
		{
			throw new OutputLengthException("output buffer too short");
		}

		if(limitExceeded(len))
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
		}

		for(int i=0; i<len; i++)
		{
			out.set(i + outOff, (byte)(keyStream.get(index) ^ in[i + inOff]));
			index = (index + 1) & 63;

			if(index == 0)
			{
				advanceCounter();
				generateKeyStream(keyStream);
			}
		}

		return len;
	}


	public int processBytes(CByteArray in, int inOff, int len, CByteArray out, int outOff)
	{
		if(!initialised)
		{
			throw new IllegalStateException(getAlgorithmName() + " not initialised");
		}

		if((inOff + len) > in.length())
		{
			throw new DataLengthException("input buffer too short");
		}

		if((outOff + len) > out.length())
		{
			throw new OutputLengthException("output buffer too short");
		}

		if(limitExceeded(len))
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
		}

		for(int i = 0; i < len; i++)
		{
			out.set(i + outOff, (byte)(keyStream.get(index) ^ in.get(i + inOff)));
			index = (index + 1) & 63;

			if(index == 0)
			{
				advanceCounter();
				generateKeyStream(keyStream);
			}
		}

		return len;
	}
	
	
	public int processBytes(CByteArray in, int inOff, int len, byte[] out, int outOff)
	{
		if(!initialised)
		{
			throw new IllegalStateException(getAlgorithmName() + " not initialised");
		}

		if((inOff + len) > in.length())
		{
			throw new DataLengthException("input buffer too short");
		}

		if((outOff + len) > out.length)
		{
			throw new OutputLengthException("output buffer too short");
		}

		if(limitExceeded(len))
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
		}

		for(int i = 0; i < len; i++)
		{
			out[i + outOff] = (byte)(keyStream.get(index) ^ in.get(i + inOff));
			index = (index + 1) & 63;

			if(index == 0)
			{
				advanceCounter();
				generateKeyStream(keyStream);
			}
		}

		return len;
	}


	public long skip(long numberOfBytes)
	{
		if(numberOfBytes >= 0)
		{
			long remaining = numberOfBytes;

			if(remaining >= 64)
			{
				long count = remaining / 64;

				advanceCounter(count);

				remaining -= count * 64;
			}

			int oldIndex = index;

			index = (index + (int)remaining) & 63;

			if(index < oldIndex)
			{
				advanceCounter();
			}
		}
		else
		{
			long remaining = -numberOfBytes;

			if(remaining >= 64)
			{
				long count = remaining / 64;

				retreatCounter(count);

				remaining -= count * 64;
			}

			for(long i = 0; i < remaining; i++)
			{
				if(index == 0)
				{
					retreatCounter();
				}

				index = (index - 1) & 63;
			}
		}

		generateKeyStream(keyStream);

		return numberOfBytes;
	}


	public long seekTo(long position)
	{
		reset();

		return skip(position);
	}


	public long getPosition()
	{
		return getCounter() * 64 + index;
	}


	public void reset()
	{
		index = 0;
		resetLimitCounter();
		resetCounter();

		generateKeyStream(keyStream);
	}


	protected long getCounter()
	{
		return ((long)engineState.get(9) << 32) | (engineState.get(8) & 0xffffffffL);
	}


	protected void resetCounter()
	{
		engineState.set(8, 0);
		engineState.set(9, 0);
	}


	protected void setKey(CByteArray keyBytes, CByteArray ivBytes)
	{
		if(keyBytes != null)
		{
			if((keyBytes.length() != 16) && (keyBytes.length() != 32))
			{
				throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
			}

			int tsOff = (keyBytes.length() - 16) / 4;
			engineState.set(0, TAU_SIGMA[tsOff]);
			engineState.set(5, TAU_SIGMA[tsOff + 1]);
			engineState.set(10, TAU_SIGMA[tsOff + 2]);
			engineState.set(15, TAU_SIGMA[tsOff + 3]);

			// Key
			CUtils.littleEndianToInt(keyBytes, 0, engineState, 1, 4);
			CUtils.littleEndianToInt(keyBytes, keyBytes.length() - 16, engineState, 11, 4);
		}

		// IV
		CUtils.littleEndianToInt(ivBytes, 0, engineState, 6, 2);
	}


	protected void generateKeyStream(CByteArray output)
	{
		salsaCore(rounds, engineState, x);
		CUtils.intToLittleEndian(x, output, 0);
	}


	/**
	 * Salsa20 function
	 *
	 * @param   input   input data
	 */
	public static void salsaCore(int rounds, CIntArray input, CIntArray x)
	{
		if(input.length() != 16)
		{
			throw new IllegalArgumentException();
		}
		if(x.length() != 16)
		{
			throw new IllegalArgumentException();
		}
		if(rounds % 2 != 0)
		{
			throw new IllegalArgumentException("Number of rounds must be even");
		}

		int x00 = input.get(0);
		int x01 = input.get(1);
		int x02 = input.get(2);
		int x03 = input.get(3);
		int x04 = input.get(4);
		int x05 = input.get(5);
		int x06 = input.get(6);
		int x07 = input.get(7);
		int x08 = input.get(8);
		int x09 = input.get(9);
		int x10 = input.get(10);
		int x11 = input.get(11);
		int x12 = input.get(12);
		int x13 = input.get(13);
		int x14 = input.get(14);
		int x15 = input.get(15);

		for(int i = rounds; i > 0; i -= 2)
		{
			x04 ^= Integer.rotateLeft(x00 + x12, 7);
			x08 ^= Integer.rotateLeft(x04 + x00, 9);
			x12 ^= Integer.rotateLeft(x08 + x04, 13);
			x00 ^= Integer.rotateLeft(x12 + x08, 18);
			x09 ^= Integer.rotateLeft(x05 + x01, 7);
			x13 ^= Integer.rotateLeft(x09 + x05, 9);
			x01 ^= Integer.rotateLeft(x13 + x09, 13);
			x05 ^= Integer.rotateLeft(x01 + x13, 18);
			x14 ^= Integer.rotateLeft(x10 + x06, 7);
			x02 ^= Integer.rotateLeft(x14 + x10, 9);
			x06 ^= Integer.rotateLeft(x02 + x14, 13);
			x10 ^= Integer.rotateLeft(x06 + x02, 18);
			x03 ^= Integer.rotateLeft(x15 + x11, 7);
			x07 ^= Integer.rotateLeft(x03 + x15, 9);
			x11 ^= Integer.rotateLeft(x07 + x03, 13);
			x15 ^= Integer.rotateLeft(x11 + x07, 18);

			x01 ^= Integer.rotateLeft(x00 + x03, 7);
			x02 ^= Integer.rotateLeft(x01 + x00, 9);
			x03 ^= Integer.rotateLeft(x02 + x01, 13);
			x00 ^= Integer.rotateLeft(x03 + x02, 18);
			x06 ^= Integer.rotateLeft(x05 + x04, 7);
			x07 ^= Integer.rotateLeft(x06 + x05, 9);
			x04 ^= Integer.rotateLeft(x07 + x06, 13);
			x05 ^= Integer.rotateLeft(x04 + x07, 18);
			x11 ^= Integer.rotateLeft(x10 + x09, 7);
			x08 ^= Integer.rotateLeft(x11 + x10, 9);
			x09 ^= Integer.rotateLeft(x08 + x11, 13);
			x10 ^= Integer.rotateLeft(x09 + x08, 18);
			x12 ^= Integer.rotateLeft(x15 + x14, 7);
			x13 ^= Integer.rotateLeft(x12 + x15, 9);
			x14 ^= Integer.rotateLeft(x13 + x12, 13);
			x15 ^= Integer.rotateLeft(x14 + x13, 18);
		}

		x.set(0, x00 + input.get(0));
		x.set(1, x01 + input.get(1));
		x.set(2, x02 + input.get(2));
		x.set(3, x03 + input.get(3));
		x.set(4, x04 + input.get(4));
		x.set(5, x05 + input.get(5));
		x.set(6, x06 + input.get(6));
		x.set(7, x07 + input.get(7));
		x.set(8, x08 + input.get(8));
		x.set(9, x09 + input.get(9));
		x.set(10, x10 + input.get(10));
		x.set(11, x11 + input.get(11));
		x.set(12, x12 + input.get(12));
		x.set(13, x13 + input.get(13));
		x.set(14, x14 + input.get(14));
		x.set(15, x15 + input.get(15));
	}


	private void resetLimitCounter()
	{
		cW0 = 0;
		cW1 = 0;
		cW2 = 0;
	}


	private boolean limitExceeded()
	{
		if(++cW0 == 0)
		{
			if(++cW1 == 0)
			{
				return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
			}
		}

		return false;
	}


	/*
	 * this relies on the fact len will always be positive.
	 */
	private boolean limitExceeded(int len)
	{
		cW0 += len;
		if(cW0 < len && cW0 >= 0)
		{
			if(++cW1 == 0)
			{
				return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
			}
		}

		return false;
	}
	
	
	public void zero()
	{
		keyStream.zero();
		x.zero();
		engineState.zero();
	}
}
