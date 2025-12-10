package com.notary.model.request;

// 请求签署的类

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignRequest {
    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("msg_hash")
    private String msgHash;

    @JsonProperty("auth_code")
    private String authCode;

    @JsonProperty("client_ts_ms")
    private Long clientTsMs;

    @JsonProperty("tsa_token_base64")
    private String tsaTokenBase64;

    public SignRequest() {}

    public SignRequest(String userId, String msgHash, String authCode,
                       Long clientTsMs, String tsaTokenBase64) {
        this.userId = userId;
        this.msgHash = msgHash;
        this.authCode = authCode;
        this.clientTsMs = clientTsMs;
        this.tsaTokenBase64 = tsaTokenBase64;
    }

    // Getter和Setter
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getMsgHash() { return msgHash; }
    public void setMsgHash(String msgHash) { this.msgHash = msgHash; }

    public String getAuthCode() { return authCode; }
    public void setAuthCode(String authCode) { this.authCode = authCode; }

    public Long getClientTsMs() { return clientTsMs; }
    public void setClientTsMs(Long clientTsMs) { this.clientTsMs = clientTsMs; }

    public String getTsaTokenBase64() { return tsaTokenBase64; }
    public void setTsaTokenBase64(String tsaTokenBase64) {
        this.tsaTokenBase64 = tsaTokenBase64;
    }
}