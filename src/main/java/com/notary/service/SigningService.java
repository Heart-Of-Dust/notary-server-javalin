package com.notary.service;

// 签名服务
import com.notary.model.entity.SignatureAudit;
import com.notary.model.response.SignResponse;
import com.notary.repository.UserKeyRepository;
import com.notary.repository.RedisRepository;
import com.notary.repository.SignatureAuditRepository;
import com.notary.security.CryptoService;
import com.notary.exception.NotaryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class SigningService {

    private static final Logger log = LoggerFactory.getLogger(SigningService.class);

    private final UserKeyRepository userRepo;
    private final RedisRepository redisRepo;
    private final SignatureAuditRepository signatureAuditRepo;
    private final CryptoService cryptoService;
    private final TsaValidationService tsaService;
    private final ValidationService validationService;

    public SigningService() {
        this.userRepo = new UserKeyRepository();
        this.redisRepo = new RedisRepository();
        this.signatureAuditRepo = new SignatureAuditRepository();
        this.cryptoService = new CryptoService();
        this.tsaService = new TsaValidationService();
        this.validationService = new ValidationService();
    }

    public SignResponse verifyAndSign(String userId, String msgHash,
                                      String authCode, Long clientTsMs,
                                      String tsaTokenBase64) {

        String transactionId = null;
        Long verifiedTsaTime = null;
        String signatureBase64 = null;

        try {
            // 1. 获取用户密钥
            var userVault = userRepo.findActiveVaultByUserId(userId)
                    .orElseThrow(() -> {
                        String errorMsg = "用户未找到: " + userId;
                        log.warn(errorMsg);
                        signatureAuditRepo.saveFailedSignatureAudit(userId, null, msgHash, clientTsMs, errorMsg);
                        return new NotaryException(errorMsg, 404);
                    });

            if (!"ACTIVE".equals(userVault.getStatus())) {
                String errorMsg = "用户账户未激活: " + userId;
                log.warn(errorMsg);
                signatureAuditRepo.saveFailedSignatureAudit(userId, null, msgHash, clientTsMs, errorMsg);
                throw new NotaryException(errorMsg, 403);
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
                String errorMsg = "检测到重复请求";
                log.warn("重复请求 - 用户: {}, 消息哈希: {}, 时间戳: {}", userId, msgHash, clientTsMs);
                signatureAuditRepo.saveFailedSignatureAudit(userId, null, msgHash, clientTsMs, errorMsg);
                throw new NotaryException(errorMsg, 409);
            }

            // 3. TSA验证（包含Imprint校验）
            long tsaTime = tsaService.validateToken(
                    tsaTokenBase64,
                    userId,
                    msgHash,
                    clientTsMs
            );
            verifiedTsaTime = tsaTime;

            // 4. 三方时间一致性校验
            validationService.validateTimeConsistency(
                    clientTsMs,
                    tsaTime,
                    System.currentTimeMillis()
            );

            // 5. HMAC授权验证 - 修改为使用UTF-8编码
            String expectedAuthCode = cryptoService.calculateHmac(
                    hmacSeed,
                    (msgHash + clientTsMs).getBytes(StandardCharsets.UTF_8)
            );

            if (!expectedAuthCode.equals(authCode)) {
                String errorMsg = "HMAC授权验证失败";
                log.warn("HMAC验证失败 - 用户: {}, 期望: {}, 实际: {}", userId, expectedAuthCode, authCode);
                signatureAuditRepo.saveFailedSignatureAudit(userId, null, msgHash, clientTsMs, errorMsg);
                throw new NotaryException(errorMsg, 401);
            }

            // 6. 代理签名
            byte[] signature = cryptoService.signWithEd25519(
                    privateKey,
                    (msgHash + tsaTime).getBytes(StandardCharsets.UTF_8)  // 同样使用UTF-8编码
            );
            signatureBase64 = Base64.getEncoder().encodeToString(signature);

            // 7. 设置防重放缓存
            redisRepo.setWithTtl(replayKey, "1", 300);

            // 8. 生成交易ID
            transactionId = "tx_" + Instant.now().toEpochMilli() + "_" + userId;

            // 9. 记录成功审计日志
            SignatureAudit audit = new SignatureAudit(
                    userId,
                    transactionId,
                    msgHash,
                    clientTsMs,
                    tsaTime,
                    signatureBase64,
                    "SUCCESS",
                    null
            );
            signatureAuditRepo.saveSignatureAudit(audit);

            // 10. 记录详细成功日志
            log.info("签名成功 - 用户: {}, 交易ID: {}, 消息哈希: {}, TSA时间: {}, 签名长度: {}",
                    userId, transactionId, msgHash, tsaTime, signatureBase64.length());

            // 11. 生成响应
            return new SignResponse(
                    "success",
                    transactionId,
                    tsaTime,
                    signatureBase64
            );

        } catch (NotaryException e) {
            // 记录业务异常审计日志
            signatureAuditRepo.saveFailedSignatureAudit(userId, transactionId, msgHash, clientTsMs, e.getMessage());
            log.warn("签名业务异常 - 用户: {}, 错误: {}", userId, e.getMessage());
            throw e;
        } catch (Exception e) {
            // 记录系统异常审计日志
            String errorMsg = "签名系统错误: " + e.getMessage();
            signatureAuditRepo.saveFailedSignatureAudit(userId, transactionId, msgHash, clientTsMs, errorMsg);
            log.error("签名系统异常 - 用户: {}, 错误: {}", userId, e.getMessage(), e);
            throw new NotaryException(errorMsg, 500);
        }
    }
}