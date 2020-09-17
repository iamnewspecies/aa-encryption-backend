package com.aa.encryption.controller;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

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
	
	public static final String fipId = "BANK123";
	
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
			accountResponse.setNonce(request.getNonce());
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
		}
		
		return new ResponseEntity<> (jsonResponse , status);
	}
	
	// this API is hosted by FIP
	@PostMapping("/api/v1/accounts/link")
	public ResponseEntity<AccountResponse> linkAccounts(@RequestBody AccountLinkRequest request) {
		AccountResponse accountResponse = new AccountResponse();
		HttpStatus status = HttpStatus.OK;
		try {
			
			String encryptedPayload = request.getEncryptedPayload();
			String encryptedKey = request.getEncryptedKey();
			String iv = request.getIv();
			SecretKey key = accountService.decryptSecretKey(encryptedKey, fipId);
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

}
