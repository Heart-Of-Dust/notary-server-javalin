package com.notary.exception;

import io.javalin.Javalin;
import io.javalin.http.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

public class ExceptionHandler {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void register(Javalin app) {
        app.exception(NotaryException.class, (e, ctx) -> {
            handleNotaryException((NotaryException) e, ctx);
        });

        app.exception(Exception.class, (e, ctx) -> {
            handleGenericException(e, ctx);
        });

        app.exception(IllegalArgumentException.class, (e, ctx) -> {
            handleBadRequest(e, ctx);
        });
    }

    private static void handleNotaryException(NotaryException e, Context ctx) {
        Map<String, Object> response = Map.of(
                "status", "error",
                "error_code", e.getErrorCode(),
                "message", e.getMessage(),
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(e.getStatusCode()).json(response);
    }

    private static void handleGenericException(Exception e, Context ctx) {
        Map<String, Object> response = Map.of(
                "status", "error",
                "error_code", "INTERNAL_SERVER_ERROR",
                "message", "An internal server error occurred",
                "timestamp", System.currentTimeMillis()
        );

        // 记录详细错误日志（生产环境应该使用logger）
        e.printStackTrace();

        ctx.status(500).json(response);
    }

    private static void handleBadRequest(Exception e, Context ctx) {
        Map<String, Object> response = Map.of(
                "status", "error",
                "error_code", "BAD_REQUEST",
                "message", e.getMessage(),
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(400).json(response);
    }
}