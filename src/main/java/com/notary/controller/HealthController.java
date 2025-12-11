package com.notary.controller;

// # 健康检查
import io.javalin.Javalin;
import io.javalin.http.Context;
import com.notary.repository.UserKeyRepository;
import com.notary.repository.RedisRepository;
import java.util.Map;

public class HealthController {

    private final UserKeyRepository userRepo;
    private final RedisRepository redisRepo;

    public HealthController() {
        this.userRepo = new UserKeyRepository();
        this.redisRepo = new RedisRepository();
    }

    public static void registerRoutes(Javalin app) {
        HealthController controller = new HealthController();

        app.get("/health", controller::healthCheck);
        app.get("/health/liveness", controller::livenessCheck);
        app.get("/health/readiness", controller::readinessCheck);
        app.get("/health/detailed", controller::detailedHealthCheck);
    }

    public void healthCheck(Context ctx) {
        Map<String, Object> response = Map.of(
                "status", "UP",
                "service", "Distributed Trustless Notary Service",
                "version", "0.1.0",
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(200).json(response);
    }

    public void livenessCheck(Context ctx) {
        // 简单的存活检查
        Map<String, Object> response = Map.of(
                "status", "ALIVE",
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(200).json(response);
    }

    public void readinessCheck(Context ctx) {
        boolean isReady = checkDatabaseConnection() && checkRedisConnection();

        Map<String, Object> response = Map.of(
                "status", isReady ? "READY" : "NOT_READY",
                "database", checkDatabaseConnection() ? "CONNECTED" : "DISCONNECTED",
                "redis", checkRedisConnection() ? "CONNECTED" : "DISCONNECTED",
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(isReady ? 200 : 503).json(response);
    }

    public void detailedHealthCheck(Context ctx) {
        Map<String, Object> response = Map.of(
                "status", "UP",
                "service", "Distributed Trustless Notary Service",
                "version", "0.1.0",
                "build", "2025-12-10",
                "environment", System.getenv().getOrDefault("NOTARY_ENV", "development"),
                "system", Map.of(
                        "java_version", System.getProperty("java.version"),
                        "available_processors", Runtime.getRuntime().availableProcessors(),
                        "free_memory", Runtime.getRuntime().freeMemory(),
                        "total_memory", Runtime.getRuntime().totalMemory(),
                        "max_memory", Runtime.getRuntime().maxMemory()
                ),
                "timestamp", System.currentTimeMillis()
        );

        ctx.status(200).json(response);
    }

    private boolean checkDatabaseConnection() {
        try {
            // 尝试执行一个简单的查询
            userRepo.existsById("health_check");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkRedisConnection() {
        try {
            // 尝试执行一个简单的Redis操作
            redisRepo.setWithTtl("health_check", "ping", 10);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}