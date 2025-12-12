package com.notary.repository;

import com.notary.model.entity.UserKeyVault;
import com.notary.config.DatabaseConfig;
import java.sql.*;
import java.util.Base64;
import java.util.Optional;
import javax.sql.DataSource;

public class UserKeyRepository {

    private final DataSource dataSource;

    public UserKeyRepository() {
        this.dataSource = DatabaseConfig.getDataSource();
    }

    public boolean existsById(String userId) {
        String sql = "SELECT COUNT(*) FROM notary_vault WHERE user_id = ?";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
            return false;

        } catch (SQLException e) {
            throw new RuntimeException("Database error while checking user existence", e);
        }
    }

    /**
     * 根据用户ID查找活跃状态的密钥保险库记录
     * @param userId 用户ID
     * @return 包含UserKeyVault对象的Optional，如果未找到则返回空Optional
     */
    public Optional<UserKeyVault> findActiveVaultByUserId(String userId) {
        String sql = "SELECT * FROM notary_vault WHERE user_id = ? AND status = 'ACTIVE'";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                UserKeyVault vault = new UserKeyVault();
                vault.setUserId(rs.getString("user_id"));
                vault.setHmacSeedEncrypted(rs.getBytes("hmac_seed_encrypted"));
                vault.setSigningPrivKeyEncrypted(rs.getBytes("signing_priv_key_encrypted"));
                vault.setPubKeyFingerprint(rs.getString("pub_key_fingerprint"));
                vault.setStatus(rs.getString("status"));
                vault.setCreatedAt(rs.getTimestamp("created_at").toInstant());

                return Optional.of(vault);
            }
            return Optional.empty();

        } catch (SQLException e) {
            throw new RuntimeException("Database error while fetching user vault", e);
        }
    }

    public Optional<String> findPublicKeyByUserId(String userId) {
        String sql = "SELECT signing_pub_key FROM notary_vault WHERE user_id = ? AND status = 'ACTIVE'";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                byte[] publicKey = rs.getBytes("signing_pub_key");
                return Optional.of(Base64.getEncoder().encodeToString(publicKey));
            }
            return Optional.empty();

        } catch (SQLException e) {
            throw new RuntimeException("Database error while fetching user public key", e);
        }
    }

    /**
     * 保存用户密钥保险箱数据到数据库
     * 该方法具有事务级别的唯一性检查，确保用户ID的唯一性（WORM原则）
     *
     * @param userId 用户ID，作为主键，必须唯一
     * @param hmacSeedEncrypted 加密后的HMAC种子密钥，用于消息认证码生成
     * @param signingPrivKeyEncrypted 加密后的签名私钥，用于数字签名
     * @param signingPubKey 用户的签名公钥，用于验证签名
     * @param pubKeyFingerprint 公钥指纹，用于快速识别和验证公钥
     * @throws RuntimeException 如果用户已存在（违反WORM原则）或数据库操作失败
     */
    public void saveUserVault(String userId, byte[] hmacSeedEncrypted,
                              byte[] signingPrivKeyEncrypted, byte[] signingPubKey,
                              String pubKeyFingerprint) {
        String sql = """
        INSERT INTO notary_vault 
        (user_id, hmac_seed_encrypted, signing_priv_key_encrypted, signing_pub_key, pub_key_fingerprint, status) 
        VALUES (?, ?, ?, ?, ?, 'ACTIVE')
        """;

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            conn.setAutoCommit(false);

            stmt.setString(1, userId);
            stmt.setBytes(2, hmacSeedEncrypted);
            stmt.setBytes(3, signingPrivKeyEncrypted);
            stmt.setBytes(4, signingPubKey);
            stmt.setString(5, pubKeyFingerprint);

            stmt.executeUpdate();
            conn.commit();

        } catch (SQLException e) {
            if (e.getSQLState().equals("23505")) {
                throw new RuntimeException("User already exists (WORM violation)", e);
            }
            throw new RuntimeException("Failed to save user vault", e);
        }
    }


    public void updateStatus(String userId, String status) {
        String sql = "UPDATE notary_vault SET status = ? WHERE user_id = ?";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, status);
            stmt.setString(2, userId);

            stmt.executeUpdate();

        } catch (SQLException e) {
            throw new RuntimeException("Failed to update user status", e);
        }
    }

    /**
     * 更新用户的HMAC种子（k_seed）
     */
    public void updateHmacSeed(String userId, byte[] newHmacSeedEncrypted) {
        String sql = "UPDATE notary_vault " +
                "SET hmac_seed_encrypted = ?, updated_at = CURRENT_TIMESTAMP " + // 注意：需先在表中添加updated_at字段
                "WHERE user_id = ? AND status = 'ACTIVE'";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            conn.setAutoCommit(false);

            stmt.setBytes(1, newHmacSeedEncrypted);
            stmt.setString(2, userId);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Update HMAC seed failed: user not found or inactive");
            }

            conn.commit();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to update HMAC seed", e);
        }
    }

}