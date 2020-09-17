package com.aa.encryption.utils;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AesKeyEncryption {

	public static SecretKey generateSecretKey() {
		// TODO Auto-generated method stub

		KeyGenerator keyGenerator;
		SecretKey key = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);

			// Generate Key
			key = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}

		return key;
	}

}
