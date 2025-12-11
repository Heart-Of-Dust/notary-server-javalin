package com.notary.model.response;

public class SeedRecoveryResponse {
    private String status;
    private String encryptedSeed; // 加密后的新seed
    private String recoveryReceipt; // 恢复凭证（HSM签名）

    // 构造函数、Getter和Setter
    public SeedRecoveryResponse(String status, String encryptedSeed, String recoveryReceipt) {
        this.status = status;
        this.encryptedSeed = encryptedSeed;
        this.recoveryReceipt = recoveryReceipt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getEncryptedSeed() {
        return encryptedSeed;
    }

    public void setEncryptedSeed(String encryptedSeed) {
        this.encryptedSeed = encryptedSeed;
    }

    public String getRecoveryReceipt() {
        return recoveryReceipt;
    }

    public void setRecoveryReceipt(String recoveryReceipt) {
        this.recoveryReceipt = recoveryReceipt;
    }
}