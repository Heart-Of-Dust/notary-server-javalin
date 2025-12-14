package com.notary.repository;

import com.notary.model.entity.SignatureAudit;
import com.notary.config.DatabaseConfig;
import java.sql.*;
import javax.sql.DataSource;

public class SignatureAuditRepository {

    private final DataSource dataSource;

    public SignatureAuditRepository() {
        this.dataSource = DatabaseConfig.getDataSource();
    }

    /**
     * 保存签名审计记录
     */
    public void saveSignatureAudit(SignatureAudit audit) {
        String sql = """
        INSERT INTO signature_audit_log 
        (user_id, transaction_id, msg_hash, client_ts_ms, verified_tsa_time, 
         signature, status, error_message, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)n = dataSource.getConnect
        """;

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, audit.getUserId());
            stmt.setString(2, audit.getTransactionId());
            stmt.setString(3, audit.getMsgHash());
            stmt.setLong(4, audit.getClientTsMs());
            stmt.setLong(5, audit.getVerifiedTsaTime());
            stmt.setString(6, audit.getSignature());
            stmt.setString(7, audit.getStatus());
            stmt.setString(8, audit.getErrorMessage());
            stmt.setTimestamp(9, Timestamp.from(audit.getCreatedAt()));

            stmt.executeUpdate();

        } catch (SQLException e) {
            System.err.println("保存签名审计记录失败: " + e.getMessage());
            // 这里不抛出异常，避免影响主业务流程
        }
    }

    /**
     * 保存失败的签名审计记录
     */
    public void saveFailedSignatureAudit(String userId, String transactionId,
                                         String msgHash, Long clientTsMs,
                                         String errorMessage) {
        SignatureAudit audit = new SignatureAudit(
                userId,
                transactionId != null ? transactionId : "N/A",
                msgHash,
                clientTsMs,
                0L,
                "N/A",
                "FAILED",
                errorMessage
        );
        saveSignatureAudit(audit);
    }
}