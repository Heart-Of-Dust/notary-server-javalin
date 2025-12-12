package com.notary.repository;

import com.notary.model.entity.UserKeyVault;
import com.notary.config.DatabaseConfig;
import java.sql.*;
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

    public Optional<UserKeyVault> findById(String userId) {
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

    // 在 saveUserVault 方法中，需要添加事务级别的唯一性检查
public void saveUserVault(String userId, byte[] hmacSeedEncrypted,
                          byte[] signingPrivKeyEncrypted, String pubKeyFingerprint) {
    String sql = """
        INSERT INTO notary_vault 
        (user_id, hmac_seed_encrypted, signing_priv_key_encrypted, pub_key_fingerprint, status) 
        VALUES (?, ?, ?, ?, 'ACTIVE')
        """;  // 移除了 ON CONFLICT DO NOTHING

    try (Connection conn = dataSource.getConnection();
         PreparedStatement stmt = conn.prepareStatement(sql)) {

        conn.setAutoCommit(false);

        stmt.setString(1, userId);
        stmt.setBytes(2, hmacSeedEncrypted);
        stmt.setBytes(3, signingPrivKeyEncrypted);
        stmt.setString(4, pubKeyFingerprint);

        stmt.executeUpdate();
        conn.commit();

    } catch (SQLException e) {
        if (e.getSQLState().equals("23505")) {  // 唯一性约束违反
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