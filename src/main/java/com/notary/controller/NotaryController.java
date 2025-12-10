package com.notary.controller;

// REST API控制器

import io.javalin.Javalin;
import io.javalin.http.Context;
import com.notary.model.request.RegisterRequest;
import com.notary.model.request.SignRequest;
import com.notary.service.KeyManagementService;
import com.notary.service.SigningService;
import com.notary.exception.NotaryException;

import java.util.Map;

public class NotaryController {

    private final KeyManagementService keyService;
    private final SigningService signingService;

    public NotaryController(KeyManagementService keyService,
                            SigningService signingService) {
        this.keyService = keyService;
        this.signingService = signingService;
    }

    public static void registerRoutes(Javalin app) {
        NotaryController controller = new NotaryController(
                new KeyManagementService(),
                new SigningService()
        );

        app.post("/api/v1/register", controller::handleRegister);
        app.post("/api/v1/sign", controller::handleSign);
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
}