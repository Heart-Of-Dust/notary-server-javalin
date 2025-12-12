
-- 创建密钥保险箱表
CREATE TABLE IF NOT EXISTS notary_vault (
    user_id VARCHAR(64) PRIMARY KEY,
    hmac_seed_encrypted BYTEA NOT NULL,
    signing_priv_key_encrypted BYTEA NOT NULL,
    pub_key_fingerprint VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_notary_vault_status ON notary_vault(status);
CREATE INDEX IF NOT EXISTS idx_notary_vault_created_at ON notary_vault(created_at);
CREATE INDEX IF NOT EXISTS idx_notary_vault_fingerprint ON notary_vault(pub_key_fingerprint);

-- 创建审计表（可选）
CREATE TABLE IF NOT EXISTS notary_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64),
    action_type VARCHAR(50) NOT NULL,
    action_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    status_code INTEGER,
    error_message TEXT
    );

-- 创建审计索引
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON notary_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON notary_audit_log(action_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON notary_audit_log(action_type);

-- 创建撤销表（用于密钥撤销列表）
CREATE TABLE IF NOT EXISTS key_revocation_list (
                                                   id BIGSERIAL PRIMARY KEY,
                                                   user_id VARCHAR(64) NOT NULL,
    pub_key_fingerprint VARCHAR(64) NOT NULL,
    revocation_reason VARCHAR(100),
    revoked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(64),
    CONSTRAINT fk_revocation_user FOREIGN KEY (user_id)
    REFERENCES notary_vault(user_id) ON DELETE CASCADE
    );

CREATE INDEX IF NOT EXISTS idx_revocation_fingerprint ON key_revocation_list(pub_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_revocation_timestamp ON key_revocation_list(revoked_at);

-- 修改notary_vault表，添加更新时间字段
ALTER TABLE IF EXISTS notary_vault
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- 为更新时间添加索引（可选）
CREATE INDEX IF NOT EXISTS idx_notary_vault_updated_at ON notary_vault(updated_at);

ALTER TABLE notary_vault ADD COLUMN signing_pub_key BYTEA;
