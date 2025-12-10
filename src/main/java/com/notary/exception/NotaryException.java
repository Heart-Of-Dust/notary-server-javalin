package com.notary.exception;

public class NotaryException extends RuntimeException {

    private final int statusCode;
    private final String errorCode;

    public NotaryException(String message) {
        this(message, 500, "INTERNAL_ERROR");
    }

    public NotaryException(String message, int statusCode) {
        this(message, statusCode, "NOTARY_ERROR");
    }

    public NotaryException(String message, int statusCode, String errorCode) {
        super(message);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}