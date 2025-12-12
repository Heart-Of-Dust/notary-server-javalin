package com.notary.security;

import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.*;
import java.nio.file.*;
import java.util.HashSet;
import java.util.Set;

public class HsmService {

    private PrivateKey rootPrivateKey;
    private PublicKey rootPublicKey;
    private static final String KEY_STORAGE_DIR = "hsm_keys";
    private static final String PRIVATE_KEY_FILE = KEY_STORAGE_DIR + "/root_private.key";
    private static final String PUBLIC_KEY_FILE = KEY_STORAGE_DIR + "/root_public.key";

    public HsmService() {
        // 创建密钥存储目录
        createKeyStorageDirectory();
        // 尝试从文件加载密钥，如果不存在则生成新密钥
        initRootKey();
    }

    private void createKeyStorageDirectory() {
        try {
            Files.createDirectories(Paths.get(KEY_STORAGE_DIR));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create HSM key storage directory", e);
        }
    }

    private void initRootKey() {
        try {
            // 首先尝试从文件加载现有密钥
            if (loadKeysFromFiles()) {
                System.out.println("成功从文件加载HSM根密钥对");
                return;
            }

            // 文件不存在，生成新密钥对
            System.out.println("未找到现有密钥文件，生成新的HSM根密钥对");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            KeyPair keyPair = keyGen.generateKeyPair();
            this.rootPrivateKey = keyPair.getPrivate();
            this.rootPublicKey = keyPair.getPublic();

            // 保存新生成的密钥到文件
            saveKeysToFiles();
            System.out.println("HSM根密钥对生成并保存成功");

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize HSM service", e);
        }
    }

    private boolean loadKeysFromFiles() {
        try {
            // 检查密钥文件是否存在
            if (!Files.exists(Paths.get(PRIVATE_KEY_FILE)) ||
                !Files.exists(Paths.get(PUBLIC_KEY_FILE))) {
                return false;
            }

            // 加载私钥
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            this.rootPrivateKey = keyFactory.generatePrivate(privateKeySpec);

            // 加载公钥
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            this.rootPublicKey = keyFactory.generatePublic(publicKeySpec);

            return true;

        } catch (Exception e) {
            System.err.println("加载密钥文件失败，将生成新密钥: " + e.getMessage());
            return false;
        }
    }

    private void saveKeysToFiles() {
        try {
            // 保存私钥
            byte[] privateKeyBytes = rootPrivateKey.getEncoded();
            Files.write(Paths.get(PRIVATE_KEY_FILE), privateKeyBytes,
                       StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // 保存公钥
            byte[] publicKeyBytes = rootPublicKey.getEncoded();
            Files.write(Paths.get(PUBLIC_KEY_FILE), publicKeyBytes,
                       StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // 设置文件权限（仅限所有者读写）
            setFilePermissions(PRIVATE_KEY_FILE);
            setFilePermissions(PUBLIC_KEY_FILE);

            System.out.println("HSM密钥对已保存到文件");

        } catch (Exception e) {
            throw new RuntimeException("Failed to save HSM keys to files", e);
        }
    }

    private void setFilePermissions(String filePath) {
        try {
            // 设置文件权限为仅所有者可读写
            Path path = Paths.get(filePath);
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (Exception e) {
            // 在Windows系统上可能会失败，忽略此错误
            System.out.println("设置文件权限失败（可能是不支持的操作系统）: " + e.getMessage());
        }
    }

    public byte[] signWithRootKey(byte[] data) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(rootPrivateKey);
            signature.update(data);
            byte[] signedData = signature.sign();

            System.out.println("根密钥签名成功，数据长度: " + data.length +
                    ", 签名长度: " + signedData.length);
            return signedData;

        } catch (Exception e) {
            throw new RuntimeException("HSM signing failed", e);
        }
    }


    public byte[] signWithUserKey(byte[] privateKeyBytes, byte[] data) {
        try {
            // 实际应该调用HSM硬件进行签名
            // 这里简化为软件签名（仅用于演示）
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            KeyPair tempKeyPair = keyGen.generateKeyPair();

            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(tempKeyPair.getPrivate());
            signature.update(data);
            return signature.sign();

        } catch (Exception e) {
            throw new RuntimeException("User key signing failed", e);
        }
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
    public byte[] encryptWithRootKey(byte[] data) {
        try {
            // 这里应该调用HSM硬件的加密功能
            // 简化实现：直接返回数据（实际应该使用HSM API）
            System.out.println("HSM加密数据，长度: " + data.length);
            return data;
        } catch (Exception e) {
            throw new RuntimeException("HSM encryption failed", e);
        }
    }
    public byte[] decryptWithRootKey(byte[] encryptedData) {
        try {
            // 这里应该调用HSM硬件的解密功能
            // 简化实现：直接返回数据（实际应该使用HSM API）
            System.out.println("HSM解密数据，长度: " + encryptedData.length);
            return encryptedData;
        } catch (Exception e) {
            throw new RuntimeException("HSM decryption failed", e);
        }
    }
}