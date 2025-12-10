package com.notary.security;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class CryptoService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12; // 12 bytes for GCM

    private final byte[] masterKey;
    private final SecureRandom secureRandom;

    public CryptoService() {
        // 实际应该从KMS/HSM获取，这里简化为从环境变量读取
        String masterKeyBase64 = System.getenv().getOrDefault(
                "MASTER_KEY_BASE64",
                "mF5nX9pLq2sR8wT3zY6vK1cB7dE0gH4j=" // 示例密钥，生产环境必须更换
        );
        this.masterKey = Base64.getDecoder().decode(masterKeyBase64);
        this.secureRandom = new SecureRandom();
    }

    public KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
        return keyGen.generateKeyPair();
    }

    public byte[] encryptWithMasterKey(byte[] plaintext) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // 组合 IV + 密文
        byte[] encrypted = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, IV_LENGTH);
        System.arraycopy(ciphertext, 0, encrypted, IV_LENGTH, ciphertext.length);

        return encrypted;
    }

    public byte[] decryptWithMasterKey(byte[] encrypted) throws Exception {
        if (encrypted.length < IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[encrypted.length - IV_LENGTH];

        System.arraycopy(encrypted, 0, iv, 0, IV_LENGTH);
        System.arraycopy(encrypted, IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);
        return cipher.doFinal(ciphertext);
    }

    public byte[] decryptWithRootKey(byte[] encrypted) throws Exception {
        // 实际应该使用HSM解密，这里简化为使用master key
        return decryptWithMasterKey(encrypted);
    }

    public String calculateHmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
        mac.init(keySpec);

        byte[] hmacBytes = mac.doFinal(data);
        return bytesToHex(hmacBytes);
    }

    public byte[] signWithEd25519(byte[] privateKeyBytes, byte[] data) throws Exception {
        // 实际应该使用Key对象，这里简化为使用原始字节
        Signature signature = Signature.getInstance("Ed25519");

        // 注意：实际实现应该从字节恢复PrivateKey对象
        // 这里简化为直接使用HSM服务签名
        HsmService hsmService = new HsmService();
        return hsmService.signWithUserKey(privateKeyBytes, data);
    }

    public String calculateFingerprint(byte[] publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(publicKey);
        return bytesToHex(hash);
    }

    public byte[] hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}