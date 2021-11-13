// Copyright © 2011-2021 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;
import goryachev.common.log.Log;
import goryachev.common.util.CKit;
import goryachev.memsafecrypto.ICryptoZeroable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;


/** Collection of simple operations related to cryptography */
public class Crypto
{
	protected static final Log log = Log.get("Crypto");
	
	
	public static void zero(ICryptoZeroable z)
	{
		try
		{
			z.zero();
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static void zero(CipherParameters p)
	{
		try
		{
			if(p != null)
			{
				if(p instanceof KeyParameter)
				{
					zero(((KeyParameter)p).getKey());
				}
				else if(p instanceof ParametersWithIV)
				{
					zero(((ParametersWithIV)p).getParameters());
				}
				else
				{
					// should not see this in production
					throw new Error("unknown " + p.getClass());
				}
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static final void zero(OpaqueMemObject x)
	{
		try
		{
			if(x != null)
			{
				x.clear();
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}

	
	public static final void zero(byte[] b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b, (byte)0);
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static final void zero(char[] b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b, '\u0000');
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static final void zero(CharBuffer b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b.array(), '\u0000');
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static final void zero(ByteBuffer b)
	{
		try
		{
			if(b != null)
			{
				Arrays.fill(b.array(), (byte)0);
			}
		}
		catch(Throwable e)
		{
			log.error(e);
		}
	}
	
	
	public static RSAPublicKey toRSAPublicKey(RSAPublicKeySpec k)
	{
		return new RSAPublicKey(k.getModulus(), k.getPublicExponent());
	}
	
	
	public static byte[] toByteArray(RSAPublicKeySpec spec) throws Exception
	{
		RSAPublicKey k = toRSAPublicKey(spec);
		return k.getEncoded();
	}
	
	
	public static RSAPrivateKey toRSAPrivateKey(RSAPrivateCrtKeyParameters k) throws Exception
	{
		// hope this is correct
		return new RSAPrivateKey
		(
			k.getModulus(), 
			k.getPublicExponent(),
			k.getExponent(),
			k.getP(),
			k.getQ(),
			k.getDP(),
			k.getDQ(),
			k.getQInv()
		);
	}
	

	public static RSAPublicKey toRSAPublicKey(RSAKeyParameters k) throws Exception
	{
		return new RSAPublicKey(k.getModulus(), k.getExponent());
	}


	public static byte[] toByteArray(RSAKeyParameters spec) throws Exception
	{
		if(spec instanceof RSAPrivateCrtKeyParameters)
		{
			RSAPrivateKey k = toRSAPrivateKey((RSAPrivateCrtKeyParameters)spec);
			return k.getEncoded();
		}
		else
		{
			RSAPublicKey k = toRSAPublicKey(spec);
			return k.getEncoded();
		}
	}
	
	
	public static APrivateKey getRSAPrivateKey(byte[] b) throws Exception
	{
		ASN1InputStream in = new ASN1InputStream(b);
		try
		{
			ASN1Primitive x = in.readObject();
			RSAPrivateKey k = RSAPrivateKey.getInstance(x);
	
			return new APrivateKey(new RSAPrivateCrtKeyParameters
			(
				k.getModulus(), 
				k.getPublicExponent(),
				k.getPrivateExponent(),
				k.getPrime1(),
				k.getPrime2(),
				k.getExponent1(),
				k.getExponent2(),
				k.getCoefficient()
			));
		}
		finally
		{
			CKit.close(in);
		}
	}
	
	
	public static APublicKey getRSAPublicKey(byte[] b) throws Exception
	{
		ASN1InputStream in = new ASN1InputStream(b);
		try
		{
			ASN1Primitive x = in.readObject();
			RSAPublicKey k = RSAPublicKey.getInstance(x);
	
			return new APublicKey(new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent()));
		}
		finally
		{
			CKit.close(in);
		}
	}
	
	
	public static CipherParameters getCipherParameters(AKey k) throws Exception
	{
		Object x = k.getKey();
		if(x instanceof CipherParameters)
		{
			return (CipherParameters)x;
		}
		else
		{
			throw new Exception("no CipherParameters in " + CKit.getSimpleName(x));
		}
	}
	
	
	public static byte[] toByteArray(Object x) throws Exception
	{
		if(x instanceof APublicKey)
		{
			return toByteArray(((APublicKey)x).getKey());
		}
		if(x instanceof APrivateKey)
		{
			return toByteArray(((APrivateKey)x).getKey());
		}
		else if(x instanceof ASN1Object)
		{
			return ((ASN1Object)x).getEncoded();
		}
		else if(x instanceof RSAPublicKeySpec)
		{
			return toByteArray((RSAPublicKeySpec)x);
		}
		else if(x instanceof RSAKeyParameters)
		{
			return toByteArray((RSAKeyParameters)x);
		}
		else
		{
			throw new Exception("don't know how to convert " + CKit.getSimpleName(x) + " to byte[]");
		}
	}

	
	/** 
	 * Generates RSA key pair with the specified key size in bits and strength.
	 * See http://stackoverflow.com/questions/3087049/bouncy-castle-rsa-keypair-generation-using-lightweight-api
	 * suggested strength = 80000
	 * keySizeBits = 4096
	 */
	public static AKeyPair createRSAKeyPair(int keySizeBits, int strength) throws Exception
	{
		BigInteger publicExponent = BigInteger.valueOf(0x10001);
		SecureRandom rnd = new SecureRandom();
		RSAKeyGenerationParameters p = new RSAKeyGenerationParameters(publicExponent, rnd, keySizeBits, strength);
		
		RSAKeyPairGenerator g = new RSAKeyPairGenerator();
		g.init(p);

		AsymmetricCipherKeyPair kp = g.generateKeyPair();
		RSAPrivateCrtKeyParameters pri = (RSAPrivateCrtKeyParameters)kp.getPrivate();
		RSAKeyParameters pub = (RSAKeyParameters)kp.getPublic();
		
		return new AKeyPair(new APrivateKey(pri), new APublicKey(pub));
	}
	
	
	public static void verifySignatureSHA256(APublicKey publicKey, byte[] payload, byte[] sig) throws Exception
	{
		CipherParameters pub = getCipherParameters(publicKey);
		RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
		signer.init(false, pub);
		signer.update(payload, 0, payload.length);
		if(!signer.verifySignature(sig))
		{
			throw new Exception("failed signature verification");
		}
	}
	
	
	public static byte[] generateSignatureSHA256(APrivateKey privateKey, byte[] payload) throws Exception
	{
		CipherParameters pub = getCipherParameters(privateKey);
		RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
		signer.init(true, pub);
		signer.update(payload, 0, payload.length);
		return signer.generateSignature();
	}
	
	
	public static byte[] encryptKeyRSA(AKey encryptionKey, ASecretKey toBeEncrypted) throws Exception
	{
		PKCS1Encoding rsa = new PKCS1Encoding(new RSAEngine());
		rsa.init(true, getCipherParameters(encryptionKey));
		
		byte[] k = toBeEncrypted.toByteArray();
		try
		{
			byte[] encrypted = rsa.processBlock(k, 0, k.length);
			return encrypted;
		}
		finally
		{
			Crypto.zero(k);
		}
	}
	
	
	public static ASecretKey decryptKeyRSA(AKey encryptionKey, byte[] b) throws Exception
	{
		PKCS1Encoding rsa = new PKCS1Encoding(new RSAEngine());
		rsa.init(false, getCipherParameters(encryptionKey));
		
		byte[] decrypted = rsa.processBlock(b, 0, b.length);
		try
		{
			return new ASecretKey(decrypted);
		}
		finally
		{
			Crypto.zero(decrypted);
		}
	}
	
	
	public static byte[] copy(byte[] key)
	{
		if(key == null)
		{
			return null;
		}
		byte[] rv = new byte[key.length];
		System.arraycopy(key, 0, rv, 0, key.length);
		return rv;
	}
	
	
	public static byte[] chars2bytes(char[] cs)
	{
		if(cs == null)
		{
			return null;
		}
		
		int sz = cs.length;
		byte[] b = new byte[sz + sz];
		int ix = 0;
		for(int i=0; i<sz; i++)
		{
			int c = cs[i];
			b[ix++] = (byte)(c >>> 8);
			b[ix++] = (byte)c;
		}
		return b;
	}
	
	
	public static char[] bytes2chars(byte[] b)
	{
		if(b == null)
		{
			return null;
		}
		
		int sz = b.length/2;
		char[] cs = new char[sz];
		int ix = 0;
		for(int i=0; i<sz; i++)
		{
			int c = (b[ix++] & 0xff) << 8;
			c |= (b[ix++] & 0xff);
			cs[i] = (char)c;
		}
		
		return cs;
	}
}
