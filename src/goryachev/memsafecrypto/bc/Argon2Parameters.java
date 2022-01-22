package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;


/**
 * @see https://www.rfc-editor.org/rfc/rfc9106.html
 */
public class Argon2Parameters
{
	public static final int ARGON2_d = 0x00;
	public static final int ARGON2_i = 0x01;
	public static final int ARGON2_id = 0x02;

	public static final int ARGON2_VERSION_10 = 0x10;
	public static final int ARGON2_VERSION_13 = 0x13;

	private static final int DEFAULT_ITERATIONS = 3;
	private static final int DEFAULT_MEMORY_COST = 12;
	private static final int DEFAULT_LANES = 1;
	private static final int DEFAULT_TYPE = ARGON2_i;
	private static final int DEFAULT_VERSION = ARGON2_VERSION_13;

	private final CByteArray salt;
	private final CByteArray secret;
	private final CByteArray additional;
	private final int iterations;
	private final int memory;
	private final int lanes;
	private final int version;
	private final int type;
	private final CharToByteConverter converter;
	

	/**
	 * @param version: either ARGON2_VERSION_10 or ARGON2_VERSION_13
	 */
	protected Argon2Parameters(int type, CByteArray salt, CByteArray secret, CByteArray additional, int iterations, int memory, int lanes, int version, CharToByteConverter converter)
	{
		this.salt = CByteArray.readOnly(salt);
		this.secret = CByteArray.readOnly(secret);
		this.additional = CByteArray.readOnly(additional);
		this.iterations = iterations;
		this.memory = memory;
		this.lanes = lanes;
		this.version = version;
		this.type = type;
		this.converter = converter;
	}


	public CByteArray getSalt()
	{
		return salt;
	}


	public CByteArray getSecret()
	{
		return secret;
	}


	public CByteArray getAdditional()
	{
		return additional;
	}


	public int getIterations()
	{
		return iterations;
	}


	public int getMemory()
	{
		return memory;
	}


	public int getLanes()
	{
		return lanes;
	}


	public int getVersion()
	{
		return version;
	}


	public int getType()
	{
		return type;
	}


	public CharToByteConverter getCharToByteConverter()
	{
		return converter;
	}


	public void clear()
	{
		Crypto.zero(salt);
		Crypto.zero(secret);
		Crypto.zero(additional);
	}
	
	
	//
	
	
	/** 
	 * Builder does not create copies of secret material, only build does that.
	 * The caller must invoke build() and zero the arguments.  
	 * The resulting Argon2Parameters will contain copies of the secrets.
	 */
	public static class Builder
	{
		private CByteArray salt;
		private CByteArray secret;
		private CByteArray additional;
		private int iterations;
		private int memory;
		private int lanes;
		private int version;
		private final int type;
		private CharToByteConverter converter = PasswordConverter.UTF8;

		
		/** creates a Builder with type ARGON2_i */
		public Builder()
		{
			this(DEFAULT_TYPE);
		}


		/**
		 * @param type - either ARGON2_d, ARGON2_i, or ARGON2_id
		 */
		public Builder(int type)
		{
			this.type = type;
			this.lanes = DEFAULT_LANES;
			this.memory = 1 << DEFAULT_MEMORY_COST;
			this.iterations = DEFAULT_ITERATIONS;
			this.version = DEFAULT_VERSION;
		}


		/**
		 * @param parallelism - degree of parallelism p determines how many independent (but synchronizing)
		 * computational chains (lanes) can be run. 
		 * It MUST be an integer value from 1 to 2^(24)-1.
		 */
		public Builder withParallelism(int parallelism)
		{
			this.lanes = parallelism;
			return this;
		}


		/**
		 * @param salt - Nonce S, which is a salt for password hashing applications. 
		 * It MUST have a length not greater than 2^(32)-1 bytes. 
		 * 16 bytes is RECOMMENDED for password hashing. 
		 * The salt SHOULD be unique for each password.
		 */
		public Builder withSalt(CByteArray salt)
		{
			this.salt = salt;
			return this;
		}


		/**
		 * @param secret - Secret value K is OPTIONAL. 
		 * If used, it MUST have a length not greater than 2^(32)-1 bytes.
		 */
		public Builder withSecret(CByteArray secret)
		{
			this.secret = secret;
			return this;
		}


		/**
		 * @param addiitonal - Associated data X is OPTIONAL.
		 * If used, it MUST have a length not greater than 2^(32)-1 bytes.
		 */
		public Builder withAdditional(CByteArray additional)
		{
			this.additional = additional;
			return this;
		}


		/**
		 * @param iterations - Number of passes t (used to tune the running time independently of the memory size)
		 * MUST be an integer number from 1 to 2^(32)-1.
		 */
		public Builder withIterations(int iterations)
		{
			this.iterations = iterations;
			return this;
		}


		/**
		 * @param memory - Memory size m MUST be an integer number of kibibytes from 8*p to 2^(32)-1.
		 * The actual number of blocks is m', which is m rounded down to the nearest multiple of 4*p.
		 */
		public Builder withMemoryAsKB(int memory)
		{
			this.memory = memory;
			return this;
		}


		public Builder withMemoryPowOfTwo(int memory)
		{
			this.memory = 1 << memory;
			return this;
		}


		/** @param version - either ARGON2_VERSION_10 or ARGON2_VERSION_13 (default) */
		public Builder withVersion(int version)
		{
			this.version = version;
			return this;
		}


		public Builder withCharToByteConverter(CharToByteConverter converter)
		{
			this.converter = converter;
			return this;
		}


		public Argon2Parameters build()
		{
			return new Argon2Parameters(type, salt, secret, additional, iterations, memory, lanes, version, converter);
		}


		public void clear()
		{
			Crypto.zero(salt);
			Crypto.zero(secret);
			Crypto.zero(additional);
		}
	}
}
