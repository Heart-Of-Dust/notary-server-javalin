package com.notary.service;

// 签名服务
import com.notary.model.response.SignResponse;
import com.notary.repository.UserKeyRepository;
import com.notary.repository.RedisRepository;
import com.notary.security.CryptoService;
import com.notary.exception.NotaryException;
import java.time.Instant;
import java.util.Base64;

public class SigningService {

    private final UserKeyRepository userRepo;
    private final RedisRepository redisRepo;
    private final CryptoService cryptoService;
    private final TsaValidationService tsaService;
    private final ValidationService validationService;

    public SigningService() {
        this.userRepo = new UserKeyRepository();
        this.redisRepo = new RedisRepository();
        this.cryptoService = new CryptoService();
        this.tsaService = new TsaValidationService();
        this.validationService = new ValidationService();
    }

    public SignResponse verifyAndSign(String userId, String msgHash,
                                      String authCode, Long clientTsMs,
                                      String tsaTokenBase64) {

        try {
            // 1. 获取用户密钥
            var userVault = userRepo.findById(userId)
                    .orElseThrow(() -> new NotaryException("User not found", 404));

            if (!"ACTIVE".equals(userVault.getStatus())) {
                throw new NotaryException("User account is not active", 403);
            }

            // 解密HMAC种子和私钥
            byte[] hmacSeed = cryptoService.decryptWithMasterKey(
                    userVault.getHmacSeedEncrypted()
            );
            byte[] privateKey = cryptoService.decryptWithMasterKey(
                    userVault.getSigningPrivKeyEncrypted()
            );

            // 2. 防重放检查
            String replayKey = String.format("dedup:%s:%s:%d",
                    userId, msgHash, clientTsMs);

            if (redisRepo.exists(replayKey)) {
                throw new NotaryException("Duplicate request detected", 409);
            }

            // 3. TSA验证（包含Imprint校验）
            long tsaTime = tsaService.validateToken(
                    tsaTokenBase64,
                    userId,
                    msgHash,
                    clientTsMs
            );

            // 4. 三方时间一致性校验
            validationService.validateTimeConsistency(
                    clientTsMs,
                    tsaTime,
                    System.currentTimeMillis()
            );

            // 5. HMAC授权验证
            String expectedAuthCode = cryptoService.calculateHmac(
                    hmacSeed,
                    (msgHash + clientTsMs).getBytes()
            );

            if (!expectedAuthCode.equals(authCode)) {
                throw new NotaryException("HMAC authorization failed", 401);
            }

            // 6. 代理签名
            byte[] signature = cryptoService.signWithEd25519(
                    privateKey,
                    (msgHash + tsaTime).getBytes()
            );

            // 7. 设置防重放缓存
            redisRepo.setWithTtl(replayKey, "1", 300);

            // 8. 生成响应
            return new SignResponse(
                    "success",
                    "tx_" + Instant.now().toEpochMilli() + "_" + userId,
                    tsaTime,
                    Base64.getEncoder().encodeToString(signature)
            );

        } catch (NotaryException e) {
            throw e;
        } catch (Exception e) {
            throw new NotaryException("Signing failed: " + e.getMessage(), 500);
        }
    }
}
