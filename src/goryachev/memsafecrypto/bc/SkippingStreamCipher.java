package goryachev.memsafecrypto.bc;


/**
 * General interface for a stream cipher that supports skipping.
 */
public interface SkippingStreamCipher
	extends StreamCipher, SkippingCipher
{
}
