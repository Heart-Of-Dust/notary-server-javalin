package com.notary.interceptor;

import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * 请求日志拦截器
 * 记录所有API请求的详细信息，用于调试和监控
 */
public class RequestLoggingInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingInterceptor.class);
    
    /**
     * 在请求处理前记录请求信息
     */
    public static void logRequest(Context ctx) {
        String method = ctx.method().name();
        String path = ctx.path();
        String userAgent = ctx.userAgent();
        String remoteAddress = ctx.ip();
        String contentType = ctx.contentType();
        
        // 记录请求头信息
        Map<String, String> headers = new HashMap<>();
        ctx.headerMap().forEach((key, value) -> {
            if (value != null && !value.isEmpty()) {
                headers.put(key, value);
            }
        });
        
        // 记录查询参数
        Map<String, String> queryParams = new HashMap<>();
        ctx.queryParamMap().forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                queryParams.put(key, String.join(",", values));
            }
        });
        
        // 记录请求体（仅对文本类型请求，避免记录二进制数据）
        String body = "";
        if (contentType != null && contentType.startsWith("application/")) {
            try {
                body = ctx.body();
                // 限制请求体长度，避免日志过长
                if (body.length() > 1000) {
                    body = body.substring(0, 1000) + "... [truncated]";
                }
            } catch (Exception e) {
                body = "[Unable to read request body]";
            }
        }
        
        logger.info("=== API请求开始 ===");
        logger.info("方法: {}", method);
        logger.info("路径: {}", path);
        logger.info("远程地址: {}", remoteAddress);
        logger.info("User-Agent: {}", userAgent);
        logger.info("Content-Type: {}", contentType);
        
        if (!queryParams.isEmpty()) {
            logger.info("查询参数: {}", queryParams);
        }
        
        if (!headers.isEmpty()) {
            // 只记录重要的请求头
            Map<String, String> importantHeaders = new HashMap<>();
            importantHeaders.put("Authorization", headers.containsKey("Authorization") ? "[REDACTED]" : "N/A");
            importantHeaders.put("X-Request-ID", headers.getOrDefault("X-Request-ID", "N/A"));
            importantHeaders.put("Accept", headers.getOrDefault("Accept", "N/A"));
            
            logger.info("重要请求头: {}", importantHeaders);
        }
        
        if (!body.isEmpty()) {
            logger.info("请求体: {}", body);
        }
        
        // 记录请求开始时间到上下文，用于计算处理时间
        ctx.attribute("requestStartTime", System.currentTimeMillis());
    }
    
    /**
     * 在请求处理后记录响应信息
     */
    public static void logResponse(Context ctx) {
        Long startTime = ctx.attribute("requestStartTime");
        long processingTime = startTime != null ? System.currentTimeMillis() - startTime : 0;
        
        int statusCode = ctx.status() != null ? ctx.status().getCode() : 200;
        String contentType = ctx.contentType();
        
        logger.info("响应状态码: {}", statusCode);
        logger.info("响应Content-Type: {}", contentType);
        logger.info("处理时间: {}ms", processingTime);
        logger.info("=== API请求结束 ===\n");
    }
    
    /**
     * 记录异常信息
     */
    public static void logException(Context ctx, Exception e) {
        Long startTime = ctx.attribute("requestStartTime");
        long processingTime = startTime != null ? System.currentTimeMillis() - startTime : 0;
        
        logger.error("=== API请求异常 ===");
        logger.error("方法: {}", ctx.method().name());
        logger.error("路径: {}", ctx.path());
        logger.error("异常类型: {}", e.getClass().getSimpleName());
        logger.error("异常消息: {}", e.getMessage());
        logger.error("处理时间: {}ms", processingTime);
        logger.error("=== API请求异常结束 ===\n");
    }
}