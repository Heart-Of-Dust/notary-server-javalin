package com.notary.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignResponse {
    @JsonProperty("status")
    private String status;

    @JsonProperty("transaction_id")
    private String transactionId;

    @JsonProperty("verified_tsa_time")
    private Long verifiedTsaTime;

    @JsonProperty("signature")
    private String signature;

    public SignResponse() {}

    public SignResponse(String status, String transactionId,
                        Long verifiedTsaTime, String signature) {
        this.status = status;
        this.transactionId = transactionId;
        this.verifiedTsaTime = verifiedTsaTime;
        this.signature = signature;
    }

    // Getter和Setter
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }

    public Long getVerifiedTsaTime() { return verifiedTsaTime; }
    public void setVerifiedTsaTime(Long verifiedTsaTime) { this.verifiedTsaTime = verifiedTsaTime; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}