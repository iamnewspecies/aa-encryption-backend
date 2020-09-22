package com.aa.encryption.controller;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import org.apache.catalina.connector.Response;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;
import com.aa.encryption.model.AccountLinkRequest;
import com.aa.encryption.model.AccountRequest;
import com.aa.encryption.model.AccountResponse;
import com.aa.encryption.service.AccountService;

@RestController
public class AccountsController {

	@Autowired
	ResourceLoader resourceLoader;
	
	@Autowired
	AccountService accountService;

//	private static HashSet<String> usedNonce = new HashSet<String>();
	
	
	// This API is hosted by Central registry
	@SuppressWarnings("unchecked")
	@PostMapping("/api/v1/accounts/info")
	public ResponseEntity<JSONObject> getInfo(@RequestBody AccountRequest request) {
		HttpStatus status = HttpStatus.OK;
		JSONObject jsonResponse = new JSONObject();
		AccountResponse accountResponse = new AccountResponse();
		String fipId = request.getFipId();
		try {
			accountService.createCentralRegistryFiles();
			PrivateKey crPrivateKey = accountService.getPrivateKey();
			accountService.createFipFiles(fipId);
			PublicKey fipPublicKey = accountService.getFipPublicKey(fipId);
			String fipPubKeyStr = org.jose4j.base64url.Base64.encode(fipPublicKey.getEncoded());
			
			accountResponse.setPublicKey(fipPubKeyStr);
			
			// this block can be replaced with database call to check if this nonce is fresh or not.
//			synchronized (usedNonce) {
//				if(request.getNonce() != null && !request.getNonce().isEmpty() && !request.getNonce().isBlank() && !usedNonce.contains(request.getNonce())) {
//					usedNonce.add(request.getNonce());
//				} else {
//					throw new Exception("Reuse of nonce / null / blank / empty nonce");
//				}
//			}
			
			accountResponse.setNonce(request.getNonce());;
			accountResponse.setSuccess("SUCCESS");	
			
			String data = new Gson().toJson(accountResponse);
			String message = accountService.signPublicKeyWithCrPrivateKey(data, crPrivateKey);
			jsonResponse.put("protected", message.split("\\.")[0]);
			jsonResponse.put("payload", message.split("\\.")[1]);
			jsonResponse.put("signature", message.split("\\.")[2]);
			
			
		} catch (Exception e) {
			accountResponse.setSuccess("FAILED");
			accountResponse.setError(e.getMessage());
			status = HttpStatus.BAD_REQUEST;
			e.printStackTrace();
		}
		
		return new ResponseEntity<> (jsonResponse , status);
	}
	
	// this API is hosted by FIP
	@PostMapping("/api/v1/accounts/link")
	public ResponseEntity<AccountResponse> linkAccounts(@RequestBody AccountLinkRequest request) {
		final String fipId = "BANK123";
		AccountResponse accountResponse = new AccountResponse();
		HttpStatus status = HttpStatus.OK;
		try {
			
			String encryptedPayload = request.getEncryptedPayload();
			String encryptedKey = request.getEncryptedKey();
			
			PrivateKey fipPrivateKey= accountService.getFipPrivateKey(fipId);
			
			SecretKey key = accountService.decryptSecretKey(encryptedKey, fipPrivateKey);
			byte[] iv = accountService.decryptIV(encryptedKey, fipPrivateKey);
			String data = accountService.decryptUsingAES(encryptedPayload, iv, key);
			
			accountResponse.setSuccess(data);

			System.out.println(data);

		} catch (Exception e) {
			e.printStackTrace();
			accountResponse.setSuccess("FAILED");
			accountResponse.setError(e.getMessage());
			status = HttpStatus.BAD_REQUEST;
		}
		return new ResponseEntity<AccountResponse>(accountResponse, status);
	}

//	public static HashSet<String> getUsedNonce() {
//		return usedNonce;
//	}
//
//	public static void setUsedNonce(HashSet<String> usedNonce) {
//		AccountsController.usedNonce = usedNonce;
//	}

}
