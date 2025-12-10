package com.notary.config;

import io.javalin.config.JavalinConfig;
import java.time.Duration;

public class AppConfig {
    private int serverPort = 8080;
    private String dbUrl;
    private String dbUser;
    private String dbPassword;
    private String redisHost;
    private int redisPort;
    private String redisPassword;  // 添加这个字段
    private Duration replayTtl = Duration.ofSeconds(300);
    private int tsaToleranceSeconds = 90;
    private int tsaMaxAgeSeconds = 300;

    private static AppConfig instance;

    private AppConfig() {
        this.serverPort = Integer.parseInt(
                System.getenv().getOrDefault("NOTARY_PORT", "8080")
        );
        this.dbUrl = System.getenv().getOrDefault("DB_URL",
                "jdbc:postgresql://localhost:5432/notary_db");
        this.dbUser = System.getenv().getOrDefault("DB_USER", "notary_admin");
        this.dbPassword = System.getenv().getOrDefault("DB_PASSWORD", "");
        this.redisHost = System.getenv().getOrDefault("REDIS_HOST", "localhost");
        this.redisPort = Integer.parseInt(
                System.getenv().getOrDefault("REDIS_PORT", "6379")
        );
        this.redisPassword = System.getenv().getOrDefault("REDIS_PASSWORD", "");
    }

    public static AppConfig load() {
        if (instance == null) {
            instance = new AppConfig();
        }
        return instance;
    }

    // Getter方法 - 必须添加Redis密码的getter
    public int getServerPort() { return serverPort; }
    public String getDbUrl() { return dbUrl; }
    public String getDbUser() { return dbUser; }
    public String getDbPassword() { return dbPassword; }
    public String getRedisHost() { return redisHost; }
    public int getRedisPort() { return redisPort; }
    public String getRedisPassword() { return redisPassword; }  // 添加这个方法
    public Duration getReplayTtl() { return replayTtl; }
    public int getTsaToleranceSeconds() { return tsaToleranceSeconds; }
    public int getTsaMaxAgeSeconds() { return tsaMaxAgeSeconds; }

    // 还可以添加连接池配置的方法
    public int getMaxPoolSize() { return 20; }
    public int getMinIdle() { return 5; }
    public long getConnectionTimeout() { return 30000; }
    public long getIdleTimeout() { return 600000; }
    public long getMaxLifetime() { return 1800000; }
}

