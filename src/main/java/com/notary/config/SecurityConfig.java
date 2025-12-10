package com.notary.config;

// 安全配置
import io.javalin.security.RouteRole;

public class SecurityConfig {

    public enum Role implements RouteRole {
        PUBLIC,          // 公开接口
        INTERNAL,        // 内部服务接口
        ADMIN            // 管理接口
    }

    // 密钥配置
    public static class KeyConfig {
        public static final int HMAC_KEY_SIZE = 256; // bits
        public static final int AES_KEY_SIZE = 256; // bits
        public static final int TOKEN_EXPIRY_HOURS = 24;

        public static final String KEY_ALGORITHM = "Ed25519";
        public static final String SYMMETRIC_ALGORITHM = "AES/GCM/NoPadding";
        public static final String HASH_ALGORITHM = "SHA-256";
    }

    // TSA配置
    public static class TsaConfig {
        public static final int TSA_TIMEOUT_MS = 10000; // 10秒
        public static final int TSA_RETRY_COUNT = 3;
        public static final int MAX_CLOCK_SKEW_SECONDS = 90;
        public static final int MAX_TOKEN_AGE_SECONDS = 300;
    }

    // 防重放配置
    public static class ReplayConfig {
        public static final int DEFAULT_TTL_SECONDS = 300; // 5分钟
        public static final int MAX_REQUESTS_PER_MINUTE = 100;
    }
}