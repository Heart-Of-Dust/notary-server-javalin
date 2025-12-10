package com.notary.security;

import java.security.*;
import java.util.Base64;

public class HsmService {

    private PrivateKey rootPrivateKey;

    public HsmService() {
        // 实际应该从HSM加载，这里简化为从环境变量或配置文件加载
        initRootKey();
    }

    private void initRootKey() {
        try {
            // 简化的实现，实际应该使用HSM
            String rootKeyBase64 = System.getenv().getOrDefault(
                    "ROOT_PRIVATE_KEY_BASE64",
                    "MC4CAQAwBQYDK2VwBCIEIA==" // 示例密钥，生产环境必须更换
            );

            // 实际应该使用HSM API加载密钥
            // 这里简化为生成一个新密钥（仅用于演示）
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();
            this.rootPrivateKey = keyPair.getPrivate();

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize HSM service", e);
        }
    }

    public byte[] signWithRootKey(byte[] data) {
        try {
            // 实际应该调用HSM硬件进行签名
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(rootPrivateKey);
            signature.update(data);
            return signature.sign();

        } catch (Exception e) {
            throw new RuntimeException("HSM signing failed", e);
        }
    }

    public byte[] signWithUserKey(byte[] privateKeyBytes, byte[] data) {
        try {
            // 实际应该调用HSM硬件进行签名
            // 这里简化为软件签名（仅用于演示）
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            keyGen.initialize(256, new SecureRandom());
            KeyPair tempKeyPair = keyGen.generateKeyPair();

            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(tempKeyPair.getPrivate());
            signature.update(data);
            return signature.sign();

        } catch (Exception e) {
            throw new RuntimeException("User key signing failed", e);
        }
    }

    public byte[] decryptWithRootKey(byte[] encryptedData) {
        // 实际应该调用HSM解密
        // 这里简化为返回原数据（仅用于演示）
        return encryptedData;
    }

    public boolean verifyRootSignature(byte[] data, byte[] signature) {
        try {
            // 实际应该从HSM获取公钥
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();

            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            return verifier.verify(signature);

        } catch (Exception e) {
            throw new RuntimeException("HSM verification failed", e);
        }
    }
}