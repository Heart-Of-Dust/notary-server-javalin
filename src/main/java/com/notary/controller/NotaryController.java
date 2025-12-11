package com.notary.controller;

// REST API控制器

import com.notary.config.AppConfig;
import com.notary.model.request.SeedChangeRequest;
import com.notary.model.request.SeedRecoveryRequest;
import com.notary.model.response.SeedRecoveryResponse;
import com.notary.security.EphemeralKeyService;
import io.javalin.Javalin;
import io.javalin.http.Context;
import com.notary.model.request.RegisterRequest;
import com.notary.model.request.SignRequest;
import com.notary.service.KeyManagementService;
import com.notary.service.SigningService;
import com.notary.exception.NotaryException;
import java.time.Duration;
import java.util.Map;

public class NotaryController {

    private final KeyManagementService keyService;
    private final SigningService signingService;
    private final EphemeralKeyService ephemeralKeyService; // 新增：动态密钥服务
    private final Duration rotationInterval; // 新增：密钥轮换周期

    public NotaryController(KeyManagementService keyService,
                            SigningService signingService,
                            EphemeralKeyService ephemeralKeyService,
                            Duration rotationInterval) {
        this.keyService = keyService;
        this.signingService = signingService;
        this.ephemeralKeyService = ephemeralKeyService;
        this.rotationInterval = rotationInterval;
    }
    public static void registerRoutes(Javalin app) {
        // 初始化动态密钥服务（从配置获取轮换周期）
        Duration rotationInterval = AppConfig.load().getEphemeralKeyRotationInterval();
        EphemeralKeyService ephemeralKeyService = new EphemeralKeyService(rotationInterval);

        // 初始化服务时注入动态密钥服务
        NotaryController controller = new NotaryController(
                new KeyManagementService(ephemeralKeyService), // 注入到密钥管理服务
                new SigningService(),
                ephemeralKeyService, // 传入控制器
                rotationInterval
        );

        app.post("/api/v1/register", controller::handleRegister);
        app.post("/api/v1/sign", controller::handleSign);
        app.get("/api/v1/registration-public-key", controller::handleGetRegistrationPublicKey);
        // 新增seed管理路由
        app.post("/api/v1/seed/recover", controller::handleSeedRecovery);
        app.post("/api/v1/seed/change", controller::handleSeedChange);
        }

    // 处理注册请求
    public void handleRegister(Context ctx) {
        try {
            RegisterRequest request = ctx.bodyAsClass(RegisterRequest.class);

            // 验证请求
            if (request.getUserId() == null || request.getUserId().trim().isEmpty()) {
                throw new NotaryException("User ID cannot be empty", 400);
            }

            if (request.getEncryptedPayload() == null ||
                    request.getEncryptedPayload().trim().isEmpty()) {
                throw new NotaryException("Encrypted payload cannot be empty", 400);
            }

            // 执行密钥注册
            var response = keyService.registerUser(
                    request.getUserId(),
                    request.getEncryptedPayload()
            );

            ctx.status(201).json(response);

        } catch (NotaryException e) {
            if (e.getStatusCode() == 409) {
                ctx.status(409).json(
                        Map.of("error", "User already exists", "status", "conflict")
                );
            } else {
                ctx.status(e.getStatusCode()).json(
                        Map.of("error", e.getMessage(), "status", "error")
                );
            }
        } catch (Exception e) {
            ctx.status(500).json(
                    Map.of("error", "Internal server error", "status", "error")
            );
        }
    }

    // 处理签名请求
    public void handleSign(Context ctx) {
        try {
            SignRequest request = ctx.bodyAsClass(SignRequest.class);

            // 验证请求
            if (request.getUserId() == null ||
                    request.getMsgHash() == null ||
                    request.getAuthCode() == null ||
                    request.getClientTsMs() == null ||
                    request.getTsaTokenBase64() == null) {
                throw new NotaryException("Missing required fields", 400);
            }

            // 执行签名验证
            var response = signingService.verifyAndSign(
                    request.getUserId(),
                    request.getMsgHash(),
                    request.getAuthCode(),
                    request.getClientTsMs(),
                    request.getTsaTokenBase64()
            );

            ctx.status(200).json(response);

        } catch (NotaryException e) {
            if (e.getStatusCode() == 409) {
                ctx.status(409).json(
                        Map.of("error", "Verification failed", "status", "conflict")
                );
            } else {
                ctx.status(e.getStatusCode()).json(
                        Map.of("error", e.getMessage(), "status", "error")
                );
            }
        } catch (Exception e) {
            ctx.status(500).json(
                    Map.of("error", "Internal server error", "status", "error")
            );
        }
    }
    public void handleGetRegistrationPublicKey(Context ctx) {
        try {
            String publicKey = ephemeralKeyService.getCurrentPublicKeyBase64();

            ctx.status(200).json(Map.of(
                    "public_key", publicKey,
                    "expires_in", rotationInterval.toSeconds(),
                    "algorithm", "RSA-OAEP"
            ));
        } catch (Exception e) {
            ctx.status(500).json(
                    Map.of("error", "Failed to get public key", "status", "error")
            );
        }
    }
    // 处理seed恢复请求
    public void handleSeedRecovery(Context ctx) {
        try {
            SeedRecoveryRequest request = ctx.bodyAsClass(SeedRecoveryRequest.class);

            // 验证请求参数
            if (request.getUserId() == null || request.getAuthProof() == null || request.getClientPubKey() == null) {
                throw new NotaryException("Missing required fields for seed recovery", 400);
            }

            SeedRecoveryResponse response = keyService.recoverSeed(
                    request.getUserId(),
                    request.getAuthProof(),
                    request.getClientPubKey()
            );

            ctx.status(200).json(response);
        } catch (NotaryException e) {
            ctx.status(e.getStatusCode()).json(Map.of("error", e.getMessage(), "status", "error"));
        } catch (Exception e) {
            ctx.status(500).json(Map.of("error", "Seed recovery failed", "status", "error"));
        }
    }

    // 处理seed更换请求
    public void handleSeedChange(Context ctx) {
        try {
            SeedChangeRequest request = ctx.bodyAsClass(SeedChangeRequest.class);

            if (request.getUserId() == null || request.getOldAuthCode() == null || request.getNewEncryptedSeed() == null) {
                throw new NotaryException("Missing required fields for seed change", 400);
            }

            Map<String, String> response = keyService.changeSeed(
                    request.getUserId(),
                    request.getOldAuthCode(),
                    request.getNewEncryptedSeed()
            );

            ctx.status(200).json(response);
        } catch (NotaryException e) {
            ctx.status(e.getStatusCode()).json(Map.of("error", e.getMessage(), "status", "error"));
        } catch (Exception e) {
            ctx.status(500).json(Map.of("error", "Seed change failed", "status", "error"));
        }
    }
}