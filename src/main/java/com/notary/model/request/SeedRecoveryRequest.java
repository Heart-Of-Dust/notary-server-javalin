package com.notary.model.request;

public class SeedRecoveryRequest {
    private String userId;
    private String authProof; // 用户身份验证凭证（如签名的时间戳）
    private String clientPubKey; // 用户公钥（用于验证身份）

    // Getter和Setter
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getAuthProof() { return authProof; }
    public void setAuthProof(String authProof) { this.authProof = authProof; }
    public String getClientPubKey() { return clientPubKey; }
    public void setClientPubKey(String clientPubKey) { this.clientPubKey = clientPubKey; }
}