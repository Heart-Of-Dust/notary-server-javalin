package com.notary.model.request;

import com.fasterxml.jackson.annotation.JsonProperty;

// 请求注册的类
public class RegisterRequest {
    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("encrypted_payload")
    private String encryptedPayload; // Base64编码

    public RegisterRequest() {}

    public RegisterRequest(String userId, String encryptedPayload) {
        this.userId = userId;
        this.encryptedPayload = encryptedPayload;
    }

    // Getter和Setter
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getEncryptedPayload() { return encryptedPayload; }
    public void setEncryptedPayload(String encryptedPayload) {
        this.encryptedPayload = encryptedPayload;
    }
}