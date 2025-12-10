package com.notary.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RegisterResponse {
    @JsonProperty("status")
    private String status;

    @JsonProperty("user_public_key")
    private String userPublicKey;

    @JsonProperty("root_endorsement")
    private String rootEndorsement;

    @JsonProperty("confirmation_signature")
    private String confirmationSignature;

    public RegisterResponse() {}

    public RegisterResponse(String status, String userPublicKey,
                            String rootEndorsement, String confirmationSignature) {
        this.status = status;
        this.userPublicKey = userPublicKey;
        this.rootEndorsement = rootEndorsement;
        this.confirmationSignature = confirmationSignature;
    }

    // Getter和Setter
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getUserPublicKey() { return userPublicKey; }
    public void setUserPublicKey(String userPublicKey) { this.userPublicKey = userPublicKey; }

    public String getRootEndorsement() { return rootEndorsement; }
    public void setRootEndorsement(String rootEndorsement) { this.rootEndorsement = rootEndorsement; }

    public String getConfirmationSignature() { return confirmationSignature; }
    public void setConfirmationSignature(String confirmationSignature) {
        this.confirmationSignature = confirmationSignature;
    }
}