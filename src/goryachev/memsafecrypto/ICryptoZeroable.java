// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;


/**
 * Crypto Zeroable Interface.
 */
public interface ICryptoZeroable
{
	/** destroys cryptographic material */
	public void zero();
}
