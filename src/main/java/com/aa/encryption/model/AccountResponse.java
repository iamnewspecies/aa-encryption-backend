package com.aa.encryption.model;


public class AccountResponse {

	private String error;
	private String success;
	private String nonce;
	private String publicKey;

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getSuccess() {
		return success;
	}

	public void setSuccess(String success) {
		this.success = success;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String string) {
		this.nonce = string;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

}
