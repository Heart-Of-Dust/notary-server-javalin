package com.notary.model.entity;

import java.time.Instant;
import jakarta.persistence.*;

@Entity
@Table(name = "signature_audit_log")
public class SignatureAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "user_id", length = 64)
    private String userId;
    @Column(name = "transaction_id", length = 128)
    private String transactionId;
    @Column(name = "msg_hash")
    private String msgHash;
    @Column(name = "client_ts_ms")
    private Long clientTsMs;
    @Column(name = "verified_tsa_time")
    private Long verifiedTsaTime;
    @Column(name = "signature")
    private String signature;
    @Column(name = "status")
    private String status;
    @Column(name = "error_message")
    private String errorMessage;
    @Column(name = "created_at")
    private Instant createdAt;

    // 构造函数
    public SignatureAudit() {}

    public SignatureAudit(String userId, String transactionId, String msgHash,
                          Long clientTsMs, Long verifiedTsaTime, String signature,
                          String status, String errorMessage) {
        this.userId = userId;
        this.transactionId = transactionId;
        this.msgHash = msgHash;
        this.clientTsMs = clientTsMs;
        this.verifiedTsaTime = verifiedTsaTime;
        this.signature = signature;
        this.status = status;
        this.errorMessage = errorMessage;
        this.createdAt = Instant.now();
    }

    // Getter和Setter方法
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }

    public String getMsgHash() { return msgHash; }
    public void setMsgHash(String msgHash) { this.msgHash = msgHash; }

    public Long getClientTsMs() { return clientTsMs; }
    public void setClientTsMs(Long clientTsMs) { this.clientTsMs = clientTsMs; }

    public Long getVerifiedTsaTime() { return verifiedTsaTime; }
    public void setVerifiedTsaTime(Long verifiedTsaTime) { this.verifiedTsaTime = verifiedTsaTime; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}