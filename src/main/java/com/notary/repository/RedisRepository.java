package com.notary.repository;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.params.SetParams;  // 添加这个导入
import com.notary.config.AppConfig;
import java.time.Duration;

public class RedisRepository {

    private final JedisPool jedisPool;
    private final Duration defaultTtl;

    public RedisRepository() {
        AppConfig config = AppConfig.load();

        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(50);
        poolConfig.setMaxIdle(10);
        poolConfig.setMinIdle(5);
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestOnReturn(true);
        poolConfig.setTestWhileIdle(true);

        if (config.getRedisPassword() != null && !config.getRedisPassword().isEmpty()) {
            this.jedisPool = new JedisPool(poolConfig,
                    config.getRedisHost(),
                    config.getRedisPort(),
                    2000,
                    config.getRedisPassword());
        } else {
            this.jedisPool = new JedisPool(poolConfig,
                    config.getRedisHost(),
                    config.getRedisPort());
        }

        this.defaultTtl = config.getReplayTtl();
    }

    public boolean exists(String key) {
        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.exists(key);
        }
    }

    public void setWithTtl(String key, String value, long ttlSeconds) {
        try (Jedis jedis = jedisPool.getResource()) {
            jedis.setex(key, ttlSeconds, value);
        }
    }

    public void setWithDefaultTtl(String key, String value) {
        setWithTtl(key, value, defaultTtl.getSeconds());
    }

    public String get(String key) {
        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.get(key);
        }
    }

    public boolean setIfNotExists(String key, String value, long ttlSeconds) {
        try (Jedis jedis = jedisPool.getResource()) {
            // 修复：使用 SetParams
            SetParams params = SetParams.setParams()
                    .nx()       // 仅当键不存在时设置
                    .ex(ttlSeconds); // 设置过期时间（秒）
            String result = jedis.set(key, value, params);
            return "OK".equals(result);
        }
    }

    public void delete(String key) {
        try (Jedis jedis = jedisPool.getResource()) {
            jedis.del(key);
        }
    }

    public void close() {
        if (jedisPool != null && !jedisPool.isClosed()) {
            jedisPool.close();
        }
    }

    // 可选：添加更多有用的方法

    /**
     * 设置键值对（如果不存在），使用默认TTL
     */
    public boolean setIfNotExistsWithDefaultTtl(String key, String value) {
        return setIfNotExists(key, value, defaultTtl.getSeconds());
    }

    /**
     * 获取键的剩余生存时间（TTL）
     */
    public long getTtl(String key) {
        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.ttl(key);
        }
    }

    /**
     * 检查Redis连接是否健康
     */
    public boolean isHealthy() {
        try (Jedis jedis = jedisPool.getResource()) {
            return "PONG".equals(jedis.ping());
        } catch (Exception e) {
            return false;
        }
    }
}