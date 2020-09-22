package com.aa.encryption.service;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.springframework.stereotype.Service;

import com.aa.encryption.utils.EncryptionDecryptionExample;

@Service
public class AccountService {

	private static final String CR_PATH = "src/main/resources/central_registry/";
	private static final String TEMP_FIP_PATH = "src/main/resources/temp_fip/";
	private static final int GCM_TAG_LENGTH = 16;

	public void createCentralRegistryFiles() throws Exception {
		File crPrivateFile = new File(CR_PATH + "private.txt");
		File crPublicFile = new File(CR_PATH + "public.txt");
		KeyPair keyPair = EncryptionDecryptionExample.getRSAKey();
		if (!crPrivateFile.exists()) {
			crPrivateFile.createNewFile();
			FileOutputStream fileOutputStream = new FileOutputStream(crPrivateFile);
			String base64Str = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
			fileOutputStream.write(base64Str.getBytes());
			fileOutputStream.close();

		}
		if (!crPublicFile.exists()) {
			crPublicFile.createNewFile();
			FileOutputStream fileOutputStream = new FileOutputStream(crPublicFile);
			String base64Str = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
			fileOutputStream.write(base64Str.getBytes());
			fileOutputStream.close();
		}
	}

	public void createFipFiles(String fipId) throws Exception {
		File fipPrivateFile = new File(TEMP_FIP_PATH + fipId + "_private.txt");
		File fipPublicFile = new File(TEMP_FIP_PATH + fipId + "_public.txt");
		KeyPair keyPair = EncryptionDecryptionExample.getRSAKey();
		if (!fipPrivateFile.exists()) {
			fipPrivateFile.createNewFile();
			FileOutputStream fileOutputStream = new FileOutputStream(fipPrivateFile);
			fileOutputStream.write(keyPair.getPrivate().getEncoded());
			fileOutputStream.close();

		}
		if (!fipPublicFile.exists()) {
			fipPublicFile.createNewFile();
			FileOutputStream fileOutputStream = new FileOutputStream(fipPublicFile);
			fileOutputStream.write(keyPair.getPublic().getEncoded());
			fileOutputStream.close();
		}
	}

	public PrivateKey getPrivateKey() throws Exception {
		File crPrivateFile = new File(CR_PATH + "private.txt");
		byte[] data = Files.readAllBytes(crPrivateFile.toPath());
		byte[] decodedData = Base64.getDecoder().decode(data);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(decodedData));
	}

	public PublicKey getPublicKey() throws Exception {
		File crPublicFile = new File(CR_PATH + "public.txt");
		byte[] data = Files.readAllBytes(crPublicFile.toPath());
		byte[] decodedData = Base64.getDecoder().decode(data);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(new X509EncodedKeySpec(decodedData));
	}

	public PublicKey getFipPublicKey(String fipId) throws Exception {
		File fipPublicFile = new File(TEMP_FIP_PATH + fipId + "_public.txt");
		byte[] data = Files.readAllBytes(fipPublicFile.toPath());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(new X509EncodedKeySpec(data));
	}

	public PrivateKey getFipPrivateKey(String fipId) throws Exception {
		File fipPrivateFile = new File(TEMP_FIP_PATH + fipId + "_private.txt");
		byte[] data = Files.readAllBytes(fipPrivateFile.toPath());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(data));
	}

	public String signPublicKeyWithCrPrivateKey(String fipPubKeyStr, PrivateKey crPrivateKey) throws Exception {
		return EncryptionDecryptionExample.signPayload(fipPubKeyStr, crPrivateKey);
	}


	public String decryptUsingAES(String data, byte[] iv, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//		byte[] byteIV = Base64.getDecoder().decode(iv);
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
		byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(data.getBytes()));

		return new String(decryptedText);
	}

	public String encodeSecretKey(SecretKey key, String fipId) throws Exception {
		PublicKey publicKey = this.getFipPublicKey(fipId);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedText = cipher.doFinal(key.getEncoded());

		return Base64.getEncoder().encodeToString(encryptedText);
	}

	public SecretKey decryptSecretKey(String key, PrivateKey fipPrivateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, fipPrivateKey);
		byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(key.getBytes()));

		return new SecretKeySpec(decryptedText, 12, decryptedText.length - 12, "AES");
	}
	
	public byte[] decryptIV(String key, PrivateKey fipPrivateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, fipPrivateKey);
		byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(key.getBytes()));

		return Arrays.copyOfRange(decryptedText, 0, 12);
	}
}
