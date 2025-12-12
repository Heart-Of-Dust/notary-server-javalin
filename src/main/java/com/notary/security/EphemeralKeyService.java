package com.notary.security;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class EphemeralKeyService {
    private volatile KeyPair currentKeyPair;
    private final Duration rotationInterval; // 密钥轮换周期（如3天）
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public EphemeralKeyService(Duration rotationInterval) {
        this.rotationInterval = rotationInterval;
        this.currentKeyPair = generateRsaKeyPair(); // 初始生成
        startRotationTask(); // 启动定时轮换
    }

    // 生成RSA密钥对（用于注册阶段加密）
    private KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); // 2048位密钥
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    // 定时轮换密钥
    private void startRotationTask() {
        scheduler.scheduleAtFixedRate(() -> {
            currentKeyPair = generateRsaKeyPair();
            System.out.println("Ephemeral key pair rotated at " + System.currentTimeMillis());
        }, rotationInterval.toHours(), rotationInterval.toHours(), TimeUnit.HOURS);
    }

    // 提供当前公钥（Base64编码，供用户使用）
    public String getCurrentPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(currentKeyPair.getPublic().getEncoded());
    }

    // 使用当前私钥解密
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.DECRYPT_MODE, currentKeyPair.getPrivate(), oaepParams);
        return cipher.doFinal(encryptedData);
    }

    // 关闭定时任务
    public void shutdown() {
        scheduler.shutdown();
    }
}