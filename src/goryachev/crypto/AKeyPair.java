// Copyright © 2013-2022 Andy Goryachev <andy@goryachev.com>
package goryachev.crypto;


public class AKeyPair
{
	private final APrivateKey privateKey;
	private final APublicKey publicKey;
	
	
	public AKeyPair(APrivateKey privateKey, APublicKey publicKey)
	{
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}
	
	
	public APrivateKey getPrivateKey()
	{
		return privateKey;
	}
	
	
	public APublicKey getPublicKey()
	{
		return publicKey;
	}
}
