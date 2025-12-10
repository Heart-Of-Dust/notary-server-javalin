package com.notary.security;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

public class SecureKeyGenerator {

    public static byte[] generateHmacSeed() {
        try {
            // 使用完整类名 javax.crypto.KeyGenerator
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(256); // 256-bit key
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate HMAC seed", e);
        }
    }

    public static String generateHmacSeedBase64() {
        byte[] seed = generateHmacSeed();
        return Base64.getEncoder().encodeToString(seed);
    }

    public static KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate Ed25519 key pair", e);
        }
    }

    public static byte[] generateAesKey() {
        try {
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256-bit key
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate AES key", e);
        }
    }

    public static String generateRandomId(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}