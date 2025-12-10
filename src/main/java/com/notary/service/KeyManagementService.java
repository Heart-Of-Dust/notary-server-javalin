package com.notary.service;

// 密钥管理服务

import com.notary.model.response.RegisterResponse;
import com.notary.repository.UserKeyRepository;
import com.notary.security.CryptoService;
import com.notary.security.HsmService;
import com.notary.exception.NotaryException;
import java.util.Base64;

public class KeyManagementService {

    private final UserKeyRepository userRepo;
    private final CryptoService cryptoService;
    private final HsmService hsmService;

    public KeyManagementService() {
        this.userRepo = new UserKeyRepository();
        this.cryptoService = new CryptoService();
        this.hsmService = new HsmService();
    }

    public RegisterResponse registerUser(String userId, String encryptedPayload) {
        // WORM检查：用户是否已存在
        if (userRepo.existsById(userId)) {
            throw new NotaryException("User already registered", 409);
        }

        try {
            // 1. 解密payload
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPayload);
            byte[] decrypted = cryptoService.decryptWithRootKey(encryptedBytes);

            // 解析payload（假设格式为 UserID|ClientSeedKey）
            String[] parts = new String(decrypted).split("\\|");
            if (parts.length != 2) {
                throw new NotaryException("Invalid payload format", 400);
            }

            String extractedUserId = parts[0];
            String clientSeedKey = parts[1];

            // 验证UserID一致性
            if (!userId.equals(extractedUserId)) {
                throw new NotaryException("UserID mismatch", 400);
            }

            // 2. 生成Ed25519密钥对
            var keyPair = cryptoService.generateEd25519KeyPair();
            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            // 3. 加密存储
            byte[] encryptedSeed = cryptoService.encryptWithMasterKey(
                    clientSeedKey.getBytes()
            );
            byte[] encryptedPrivateKey = cryptoService.encryptWithMasterKey(
                    privateKey
            );

            // 4. 计算公钥指纹
            String fingerprint = cryptoService.calculateFingerprint(publicKey);

            // 5. 保存到数据库
            userRepo.saveUserVault(userId, encryptedSeed,
                    encryptedPrivateKey, fingerprint);

            // 6. 生成根签名背书
            byte[] endorsement = hsmService.signWithRootKey(
                    (userId + Base64.getEncoder().encodeToString(publicKey)).getBytes()
            );

            // 7. 生成客户端回执
            String receiptData = userId + clientSeedKey;
            byte[] receipt = hsmService.signWithRootKey(
                    cryptoService.hash(receiptData.getBytes())
            );

            return new RegisterResponse(
                    "success",
                    Base64.getEncoder().encodeToString(publicKey),
                    Base64.getEncoder().encodeToString(endorsement),
                    Base64.getEncoder().encodeToString(receipt)
            );

        } catch (Exception e) {
            throw new NotaryException("Registration failed: " + e.getMessage(), 500);
        }
    }
}