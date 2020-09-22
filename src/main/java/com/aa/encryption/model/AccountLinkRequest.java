package com.aa.encryption.model;

public class AccountLinkRequest {
	private String encryptedPayload;
	private String encryptedKey;
	private String iv;

	public String getEncryptedPayload() {
		return encryptedPayload;
	}

	public void setEncryptedPayload(String encryptedPayload) {
		this.encryptedPayload = encryptedPayload;
	}

	public String getEncryptedKey() {
		return encryptedKey;
	}

	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}
}
