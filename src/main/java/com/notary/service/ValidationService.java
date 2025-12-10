package com.notary.service;

// 通用验证服务
import com.notary.config.AppConfig;
import com.notary.exception.NotaryException;

public class ValidationService {

    private final AppConfig config;

    public ValidationService() {
        this.config = AppConfig.load();
    }

    public void validateTimeConsistency(long clientTs, long tsaTime, long systemTime) {
        long clientTsaDiff = Math.abs(tsaTime - clientTs);
        long systemTsaDiff = Math.abs(systemTime - tsaTime);

        // 规则A: 防扣留，确保业务服务器没有恶意扣留请求
        if (clientTsaDiff > config.getTsaToleranceSeconds() * 1000) {
            throw new NotaryException(
                    String.format("TSA time deviation too large: %dms (max: %ds)",
                            clientTsaDiff, config.getTsaToleranceSeconds()),
                    409
            );
        }

        // 规则B: 防过期，确保不是使用很久以前的TSA令牌
        if (systemTsaDiff > config.getTsaMaxAgeSeconds() * 1000) {
            throw new NotaryException(
                    String.format("TSA token too old: %dms (max: %ds)",
                            systemTsaDiff, config.getTsaMaxAgeSeconds()),
                    409
            );
        }
    }
}