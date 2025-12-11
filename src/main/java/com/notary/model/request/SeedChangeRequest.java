package com.notary.model.request;

public class SeedChangeRequest {
    private String userId;
    private String oldAuthCode; // 旧seed生成的验证码（验证所有权）
    private String newEncryptedSeed; // 客户端加密的新seed

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getOldAuthCode() {
        return oldAuthCode;
    }

    public void setOldAuthCode(String oldAuthCode) {
        this.oldAuthCode = oldAuthCode;
    }

    public String getNewEncryptedSeed() {
        return newEncryptedSeed;
    }

    public void setNewEncryptedSeed(String newEncryptedSeed) {
        this.newEncryptedSeed = newEncryptedSeed;
    }
}