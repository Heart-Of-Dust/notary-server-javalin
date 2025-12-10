package com.notary.service;

// TSA验证服务
import com.notary.exception.NotaryException;
import java.security.MessageDigest;
import java.nio.ByteBuffer;
import java.util.Base64;

public class TsaValidationService {

    public long validateToken(String tsaTokenBase64, String userId,
                              String msgHash, long clientTsMs) {
        try {
            // 解码TSA Token
            byte[] tokenBytes = Base64.getDecoder().decode(tsaTokenBase64);

            // TODO: 实际实现需要解析ASN.1格式的TSA响应
            // 这里简化处理，实际应该：
            // 1. 验证证书链
            // 2. 验证签名
            // 3. 提取MessageImprint

            // 计算预期的Imprint
            byte[] expectedImprint = calculateImprint(userId, msgHash, clientTsMs);

            // TODO: 从token中提取实际的imprint进行比较
            // 这里假设验证通过，直接返回一个模拟的TSA时间
            // 实际实现应该从token中解析出权威时间

            // 模拟：返回clientTsMs加上一个小的偏移
            return clientTsMs + 500; // 500ms偏移

        } catch (Exception e) {
            throw new NotaryException("TSA validation failed: " + e.getMessage(), 409);
        }
    }

    // 计算Imprint（文档中规定的算法）
    private byte[] calculateImprint(String userId, String msgHash, long clientTsMs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 1. UTF8编码的UserID
            digest.update(userId.getBytes("UTF-8"));

            // 2. 16进制字符串解码为字节数组
            byte[] msgHashBytes = hexStringToByteArray(msgHash);
            digest.update(msgHashBytes);

            // 3. 大端序的64位整数
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(clientTsMs);
            digest.update(buffer.array());

            return digest.digest();

        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate imprint", e);
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}