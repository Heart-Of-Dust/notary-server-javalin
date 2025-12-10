package com.notary.model.entity;

import java.time.Instant;
import jakarta.persistence.*;

@Entity
@Table(name = "notary_vault")
public class UserKeyVault {
    @Id
    @Column(name = "user_id", length = 64)
    private String userId;

    @Column(name = "hmac_seed_encrypted", nullable = false)
    private byte[] hmacSeedEncrypted;

    @Column(name = "signing_priv_key_encrypted", nullable = false)
    private byte[] signingPrivKeyEncrypted;

    @Column(name = "pub_key_fingerprint", length = 64, nullable = false)
    private String pubKeyFingerprint;

    @Column(name = "status", length = 20)
    private String status = "ACTIVE";

    @Column(name = "created_at")
    private Instant createdAt = Instant.now();

    // 构造函数
    public UserKeyVault() {}

    public UserKeyVault(String userId, byte[] hmacSeedEncrypted,
                        byte[] signingPrivKeyEncrypted, String pubKeyFingerprint) {
        this.userId = userId;
        this.hmacSeedEncrypted = hmacSeedEncrypted;
        this.signingPrivKeyEncrypted = signingPrivKeyEncrypted;
        this.pubKeyFingerprint = pubKeyFingerprint;
    }

    // Getter和Setter
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public byte[] getHmacSeedEncrypted() { return hmacSeedEncrypted; }
    public void setHmacSeedEncrypted(byte[] hmacSeedEncrypted) {
        this.hmacSeedEncrypted = hmacSeedEncrypted;
    }

    public byte[] getSigningPrivKeyEncrypted() { return signingPrivKeyEncrypted; }
    public void setSigningPrivKeyEncrypted(byte[] signingPrivKeyEncrypted) {
        this.signingPrivKeyEncrypted = signingPrivKeyEncrypted;
    }

    public String getPubKeyFingerprint() { return pubKeyFingerprint; }
    public void setPubKeyFingerprint(String pubKeyFingerprint) {
        this.pubKeyFingerprint = pubKeyFingerprint;
    }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}