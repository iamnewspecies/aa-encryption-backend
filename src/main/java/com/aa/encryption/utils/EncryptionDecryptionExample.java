package com.aa.encryption.utils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

public class EncryptionDecryptionExample {
	public static final int AES_KEY_SIZE = 256;
	public static final int RSA_KEY_SIZE = 2048;
	public static final int GCM_IV_LENGTH = 12;
	public static final int GCM_TAG_LENGTH = 16;
	public static Path source = Paths.get("src/main/resources/temp_fip/");

	// Get RSA keys. Uses key size of 2048.
	public static KeyPair getRSAKey() throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	public static String signPayload(String payload, PrivateKey privateKey) throws JoseException {
		String examplePayload = payload;
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(examplePayload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.setKey(privateKey);
		jws.setKeyIdHeaderValue("147039814738jerhklejr9047398043172h");
		String jwsCompactSerialization = jws.getCompactSerialization();

		System.out.println(jwsCompactSerialization);

		return jwsCompactSerialization;
	}
}
