package com.notary.service;

import com.notary.model.entity.UserKeyVault;
import com.notary.model.response.RegisterResponse;
import com.notary.model.response.SeedRecoveryResponse;
import com.notary.repository.UserKeyRepository;
import com.notary.security.CryptoService;
import com.notary.security.EphemeralKeyService;
import com.notary.security.HsmService;
import com.notary.exception.NotaryException;
import com.notary.security.SecureKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

/**
 * 密钥管理服务（用户注册、密钥生成与存储）
 */
public class KeyManagementService {
    // 添加日志组件，方便排查问题
    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);

    private final EphemeralKeyService ephemeralKeyService;
    private final UserKeyRepository userRepo;
    private final CryptoService cryptoService;
    private final HsmService hsmService;


    // 优化：推荐通过构造方法注入所有依赖（而非硬new），便于测试和扩展
    public KeyManagementService(EphemeralKeyService ephemeralKeyService,
                                UserKeyRepository userRepo,
                                CryptoService cryptoService,
                                HsmService hsmService) {
        this.ephemeralKeyService = ephemeralKeyService;
        this.userRepo = userRepo;
        this.cryptoService = cryptoService;
        this.hsmService = hsmService;
    }

    // 兼容原有构造方法（可选，避免调用方改造）
    public KeyManagementService(EphemeralKeyService ephemeralKeyService) {
        this(ephemeralKeyService,
                new UserKeyRepository(),
                new CryptoService(),
                new HsmService());
    }

    public RegisterResponse registerUser(String userId, String encryptedPayload) {
        // 1. WORM检查：用户是否已存在
        if (userRepo.existsById(userId)) {
            log.warn("User {} already registered (WORM check failed)", userId);
            throw new NotaryException("User already registered", 409);
        }

        try {
            // 2. 解密payload（使用动态私钥）
            log.info("Start decrypting payload for user: {}", userId);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPayload);
            byte[] decrypted;
            try {
                decrypted = ephemeralKeyService.decrypt(encryptedBytes);
            } catch (Exception e) {
                log.error("Failed to decrypt payload for user {}: {}", userId, e.getMessage(), e);
                throw new NotaryException("Payload decryption failed (invalid key or data)", 400);
            }

            // 3. 解析payload（指定UTF-8编码，避免乱码）
            String payload = new String(decrypted, StandardCharsets.UTF_8);
            String[] parts = payload.split("\\|");
            if (parts.length != 2) {
                log.error("Invalid payload format for user {}: {}", userId, payload);
                throw new NotaryException("Invalid payload format (expected: UserID|ClientSeedKey)", 400);
            }

            String extractedUserId = parts[0];
            String clientSeedKey = parts[1];

            // 4. 验证UserID一致性
            if (!userId.equals(extractedUserId)) {
                log.warn("UserID mismatch for {}: extracted={}", userId, extractedUserId);
                throw new NotaryException("UserID mismatch in payload", 400);
            }

            // 5. 生成用户永久Ed25519密钥对
            var keyPair = cryptoService.generateEd25519KeyPair();
            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            // 6. 加密存储种子和私钥
            byte[] encryptedSeed = cryptoService.encryptWithMasterKey(clientSeedKey.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedPrivateKey = cryptoService.encryptWithMasterKey(privateKey);

            // 7. 计算公钥指纹
            String fingerprint = cryptoService.calculateFingerprint(publicKey);

            // 8. 保存到数据库
            userRepo.saveUserVault(userId, encryptedSeed, encryptedPrivateKey, fingerprint);
            log.info("User {} registered successfully, fingerprint: {}", userId, fingerprint);

            // 9. 生成根签名背书
            byte[] endorsement = hsmService.signWithRootKey(
                    (userId + Base64.getEncoder().encodeToString(publicKey)).getBytes(StandardCharsets.UTF_8)
            );

            // 10. 生成客户端回执
            String receiptData = userId + clientSeedKey;
            byte[] receipt = hsmService.signWithRootKey(
                    cryptoService.hash(receiptData.getBytes(StandardCharsets.UTF_8))
            );

            // 11. 返回响应
            return new RegisterResponse(
                    "success",
                    Base64.getEncoder().encodeToString(publicKey),
                    Base64.getEncoder().encodeToString(endorsement),
                    Base64.getEncoder().encodeToString(receipt)
            );

        } catch (NotaryException e) {
            // 已知业务异常，直接抛出
            throw e;
        } catch (Exception e) {
            // 未知异常，记录日志并返回通用错误
            log.error("Unexpected error during registration for user {}: {}", userId, e.getMessage(), e);
            throw new NotaryException("Registration failed: internal server error", 500);
        }
    }
    public SeedRecoveryResponse recoverSeed(String userId, String authProof, String clientPubKey) {
        // 1. 验证用户是否存在
        if (!userRepo.existsById(userId)) {
            throw new NotaryException("User not found", 404);
        }

        // 2. 验证用户身份（通过客户端公钥和authProof）
        boolean isAuthenticated = verifyUserIdentity(userId, authProof, clientPubKey);
        if (!isAuthenticated) {
            throw new NotaryException("Identity verification failed", 401);
        }

        try {
            // 3. 生成新的seed
            String newSeed = new String(SecureKeyGenerator.generateHmacSeed());

            // 4. 用用户公钥加密新seed（客户端可解密）
            byte[] encryptedSeed = cryptoService.encryptWithPublicKey(
                    cryptoService.decodePublicKey(clientPubKey),
                    newSeed.getBytes()
            );

            // 5. 更新数据库中的seed（重新加密存储）
            byte[] encryptedSeedForStorage = cryptoService.encryptWithMasterKey(newSeed.getBytes());
            userRepo.updateHmacSeed(userId, encryptedSeedForStorage);

            // 6. 生成HSM签名的恢复凭证
            byte[] receiptData = (userId + System.currentTimeMillis()).getBytes();
            byte[] receiptSignature = hsmService.signWithRootKey(receiptData);

            // 7. 记录审计日志（可选）
            // auditService.logAction(userId, "SEED_RECOVERY", "success");

            return new SeedRecoveryResponse(
                    "success",
                    Base64.getEncoder().encodeToString(encryptedSeed),
                    Base64.getEncoder().encodeToString(receiptSignature)
            );
        } catch (Exception e) {
            // auditService.logAction(userId, "SEED_RECOVERY", "failed: " + e.getMessage());
            throw new NotaryException("Seed recovery failed: " + e.getMessage(), 500);
        }
    }

    // 辅助方法：验证用户身份
    private boolean verifyUserIdentity(String userId, String authProof, String clientPubKey) {
        try {
            // 验证authProof是用户用私钥对userId的签名
            byte[] proofBytes = Base64.getDecoder().decode(authProof);
            PublicKey publicKey = cryptoService.decodePublicKey(clientPubKey);
            return cryptoService.verifySignature(publicKey, userId.getBytes(), proofBytes);
        } catch (Exception e) {
            return false;
        }
    }

    public Map<String, String> changeSeed(String userId, String oldAuthCode, String newEncryptedSeed) {
        // 1. 验证用户存在
        UserKeyVault vault = userRepo.findById(userId)
                .orElseThrow(() -> new NotaryException("User not found", 404));

        try {
            // 2. 解密旧seed并验证oldAuthCode
            byte[] decryptedOldSeed = cryptoService.decryptWithMasterKey(vault.getHmacSeedEncrypted());
            String oldSeed = new String(decryptedOldSeed);

            // 验证oldAuthCode是否由旧seed生成（假设是HMAC结果）
            boolean isOldSeedValid = cryptoService.verifyHmac(
                    oldSeed.getBytes(),
                    userId.getBytes(),
                    Base64.getDecoder().decode(oldAuthCode)
            );
            if (!isOldSeedValid) {
                throw new NotaryException("Invalid old seed verification code", 403);
            }

            // 3. 解密客户端发送的新seed（使用动态密钥服务的私钥解密，替换原此处修复核心错误**）
            byte[] encryptedNewSeedBytes = Base64.getDecoder().decode(newEncryptedSeed);
            byte[] newSeedBytes = ephemeralKeyService.decrypt(encryptedNewSeedBytes); // 使用已有的动态密钥服务解密

            // 4. 加密新seed并更新数据库
            byte[] encryptedNewSeed = cryptoService.encryptWithMasterKey(newSeedBytes);
            userRepo.updateHmacSeed(userId, encryptedNewSeed);

            return Map.of("status", "success", "message", "Seed updated successfully");
        } catch (Exception e) {
            throw new NotaryException("Seed change failed: " + e.getMessage(), 500);
        }
    }
}