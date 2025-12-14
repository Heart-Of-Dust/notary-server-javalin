# 分布式去中心化公证服务 API 文档

## 概述

本文档详细描述了分布式去中心化公证服务（Distributed Trustless Notary Service）的API接口。该服务提供用户注册、数字签名、密钥管理和健康检查等功能，采用Ed25519签名算法、RSA-OAEP加密和HSM（硬件安全模块）保护，确保安全性和可信性。

## 基础信息

- **服务名称**: Distributed Trustless Notary Service
- **版本**: 0.1.0
- **基础URL**: `http://localhost:8080`
- **内容类型**: `application/json`
- **字符编码**: UTF-8

## 安全机制

### 加密算法
- **签名算法**: Ed25519
- **加密算法**: RSA-OAEP (SHA-256 + MGF1)
- **对称加密**: AES-GCM (256位密钥)
- **哈希算法**: SHA-256
- **HMAC算法**: HMAC-SHA256

### 密钥管理
- **根密钥**: Ed25519密钥对，存储在HSM中
- **临时密钥**: RSA-2048密钥对，定期轮换（默认3天）
- **用户密钥**: Ed25519密钥对，加密存储在数据库中
- **种子密钥**: HMAC-SHA256种子，用于生成授权码

### 防重放机制
- 使用Redis存储请求指纹，防止重复请求
- 防重放缓存时间：300秒（5分钟）

## 授权码(AuthCode)计算详解

### 概述

授权码(AuthCode)是系统中用于验证用户身份和请求合法性的关键安全机制。它基于HMAC-SHA256算法生成，确保只有拥有正确种子的用户才能生成有效的授权码。

### 计算原理

授权码使用HMAC-SHA256算法，基于用户的HMAC种子和请求数据生成。计算公式如下：

```
AuthCode = HMAC-SHA256(HMAC_Seed, MessageHash + ClientTimestamp)
```

### 计算步骤详解

1. **获取HMAC种子**
   - 从用户密钥库中获取加密的HMAC种子
   - 使用HSM主密钥解密获得原始种子
   - 种子长度：256位(32字节)

2. **构造消息数据**
   - 将消息哈希(MessageHash)和客户端时间戳(ClientTimestamp)拼接
   - 格式：`MessageHash + ClientTimestamp`
   - 示例：`"a1b2c3d4e5f6...1703123456789"`

3. **执行HMAC计算**
   - 使用HMAC-SHA256算法
   - 密钥：用户的HMAC种子
   - 数据：拼接后的消息数据
   - 输出：32字节的HMAC值

4. **编码为十六进制**
   - 将32字节的HMAC值转换为十六进制字符串
   - 最终得到64字符的授权码

### 代码实现示例

```java
// Java实现示例
public String calculateAuthCode(byte[] hmacSeed, String msgHash, long clientTsMs) {
    try {
        // 构造消息数据
        String messageData = msgHash + clientTsMs;
        
        // 创建HMAC-SHA256实例
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(hmacSeed, "HmacSHA256");
        mac.init(keySpec);
        
        // 计算HMAC值
        byte[] hmacBytes = mac.doFinal(messageData.getBytes(StandardCharsets.UTF_8));
        
        // 转换为十六进制字符串
        return bytesToHex(hmacBytes);
    } catch (Exception e) {
        throw new RuntimeException("AuthCode calculation failed", e);
    }
}
```

```javascript
// JavaScript实现示例
async function calculateAuthCode(hmacSeed, msgHash, clientTsMs) {
    // 构造消息数据
    const messageData = msgHash + clientTsMs;
    
    // 导入HMAC密钥
    const key = await crypto.subtle.importKey(
        'raw',
        hmacSeed,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // 计算HMAC签名
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(messageData)
    );
    
    // 转换为十六进制字符串
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
```

### 验证过程

服务端验证授权码的步骤：

1. **获取用户数据**
   - 从数据库获取用户的加密HMAC种子
   - 使用HSM主密钥解密获得原始种子

2. **重新计算授权码**
   - 使用相同的算法和参数重新计算授权码
   - 输入：用户HMAC种子 + 请求中的消息哈希 + 客户端时间戳

3. **比较验证**
   - 比较计算得到的授权码与请求中的授权码
   - 如果完全匹配，验证通过；否则验证失败

### 安全特性

1. **防伪造**: 只有拥有正确HMAC种子的用户才能生成有效授权码
2. **防重放**: 包含时间戳，结合防重放机制防止重复使用
3. **完整性**: HMAC算法确保数据完整性，任何修改都会导致验证失败
4. **时效性**: 时间戳确保授权码具有时效性，过期无效

### 常见错误及解决

1. **授权码不匹配**
   - 检查HMAC种子是否正确
   - 确认消息哈希和时间戳格式正确
   - 验证编码方式(UTF-8)

2. **时间戳问题**
   - 确保使用毫秒级时间戳
   - 检查时间戳是否在有效范围内
   - 验证时间戳与TSA令牌的一致性

3. **编码问题**
   - 确保消息数据使用UTF-8编码
   - 验证十六进制转换的正确性
   - 检查大小写敏感性

### 调试建议

1. **日志记录**: 记录授权码计算的中间结果
2. **分步验证**: 分别验证种子、消息数据和计算过程
3. **一致性检查**: 确保客户端和服务端使用相同的算法和参数
4. **时间同步**: 确保客户端和服务端时间同步

## API 端点

### 1. 用户注册

**端点**: `POST /api/v1/register`

**描述**: 注册新用户并生成用户密钥对

#### 请求参数

| 参数名            | 类型   | 必需 | 描述                                                |
| ----------------- | ------ | ---- | --------------------------------------------------- |
| user_id           | String | 是   | 用户唯一标识符                                      |
| encrypted_payload | String | 是   | Base64编码的加密载荷，格式为"UserID\|ClientSeedKey" |

#### 请求示例

```json
{
  "user_id": "user123",
  "encrypted_payload": "Base64编码的加密数据"
}
```

#### 响应参数

| 参数名                 | 类型   | 描述                        |
| ---------------------- | ------ | --------------------------- |
| status                 | String | 注册状态，"success"表示成功 |
| user_public_key        | String | Base64编码的用户公钥        |
| root_endorsement       | String | Base64编码的根签名背书      |
| confirmation_signature | String | Base64编码的确认签名        |

#### 响应示例

```json
{
  "status": "success",
  "user_public_key": "Base64编码的用户公钥",
  "root_endorsement": "Base64编码的根签名背书",
  "confirmation_signature": "Base64编码的确认签名"
}
```

#### 内部处理流程

1. **WORM检查**: 验证用户是否已存在，防止重复注册
2. **载荷解密**: 使用当前临时RSA私钥解密客户端发送的加密载荷
3. **格式验证**: 验证解密后的载荷格式是否为"UserID\|ClientSeedKey"
4. **身份验证**: 验证载荷中的UserID与请求中的UserID是否一致
5. **密钥生成**: 为用户生成Ed25519密钥对
6. **加密存储**: 使用HSM主密钥加密用户的种子和私钥
7. **指纹计算**: 计算用户公钥的SHA-256指纹
8. **数据库存储**: 将用户信息保存到数据库
9. **根签名**: 使用HSM根私钥对用户ID和公钥进行签名背书
10. **确认签名**: 生成客户端回执签名
11. **返回响应**: 返回注册结果和相关信息

#### 错误响应

| 状态码 | 错误信息                          | 描述                 |
| ------ | --------------------------------- | -------------------- |
| 400    | User ID cannot be empty           | 用户ID为空           |
| 400    | Encrypted payload cannot be empty | 加密载荷为空         |
| 400    | Payload decryption failed         | 载荷解密失败         |
| 400    | Invalid payload format            | 载荷格式无效         |
| 400    | UserID mismatch in payload        | 载荷中的用户ID不匹配 |
| 409    | User already exists               | 用户已存在           |
| 500    | Internal server error             | 内部服务器错误       |

---

### 2. 数字签名

**端点**: `POST /api/v1/sign`

**描述**: 对消息哈希进行数字签名

#### 请求参数

| 参数名           | 类型   | 必需 | 描述                                  |
| ---------------- | ------ | ---- | ------------------------------------- |
| user_id          | String | 是   | 用户唯一标识符                        |
| msg_hash         | String | 是   | 消息的SHA-256哈希值（十六进制字符串） |
| auth_code        | String | 是   | HMAC授权码（详见授权码计算章节）      |
| client_ts_ms     | Long   | 是   | 客户端时间戳（毫秒）                  |
| tsa_token_base64 | String | 是   | Base64编码的时间戳令牌                |

#### 请求示例

```json
{
  "user_id": "user123",
  "msg_hash": "a1b2c3d4e5f6...",
  "auth_code": "HMAC授权码",
  "client_ts_ms": 1703123456789,
  "tsa_token_base64": "Base64编码的TSA令牌"
}
```

#### 响应参数

| 参数名            | 类型   | 描述                        |
| ----------------- | ------ | --------------------------- |
| status            | String | 签名状态，"success"表示成功 |
| transaction_id    | String | 交易唯一标识符              |
| verified_tsa_time | Long   | 验证后的TSA时间戳           |
| signature         | String | Base64编码的数字签名        |

#### 响应示例

```json
{
  "status": "success",
  "transaction_id": "tx_1703123456789_user123",
  "verified_tsa_time": 1703123456000,
  "signature": "Base64编码的数字签名"
}
```

#### 内部处理流程

1. **用户验证**: 获取用户密钥库，验证用户存在且状态为ACTIVE
2. **密钥解密**: 解密用户的HMAC种子和私钥
3. **防重放检查**: 检查Redis中是否存在相同的请求指纹
4. **TSA验证**: 验证时间戳令牌的有效性和完整性
   - 验证TSA签名
   - 验证消息指纹匹配
   - 提取TSA时间
5. **时间一致性校验**: 验证客户端时间、TSA时间和系统时间的一致性
   - 客户端与TSA时间差不超过90秒
   - 系统与TSA时间差不超过300秒
6. **HMAC授权验证**: 使用用户种子验证授权码（详见授权码计算章节）
7. **数字签名**: 使用用户私钥对消息哈希和TSA时间进行签名
8. **防重放缓存**: 在Redis中设置请求指纹，防止重复请求
9. **返回响应**: 返回签名结果和相关信息

#### TSA令牌验证详细流程

1. **解码和解析**: Base64解码TSA令牌，解析CMS签名数据
2. **签名验证**: 使用TSA证书验证令牌签名
3. **指纹计算**: 计算预期消息指纹
   - UTF-8编码的用户ID
   - 十六进制解码的消息哈希
   - 大端序64位时间戳
4. **指纹匹配**: 比较令牌中的指纹与计算的指纹
5. **时间提取**: 提取TSA生成时间

#### 错误响应

| 状态码 | 错误信息                     | 描述            |
| ------ | ---------------------------- | --------------- |
| 400    | Missing required fields      | 缺少必需字段    |
| 401    | HMAC authorization failed    | HMAC授权失败    |
| 403    | User account is not active   | 用户账户未激活  |
| 404    | User not found               | 用户不存在      |
| 409    | Duplicate request detected   | 检测到重复请求  |
| 409    | TSA imprint mismatch         | TSA指纹不匹配   |
| 409    | TSA time deviation too large | TSA时间偏差过大 |
| 409    | TSA token too old            | TSA令牌过期     |
| 500    | Signing failed               | 签名失败        |

---

### 3. 获取注册公钥

**端点**: `GET /api/v1/registration-public-key`

**描述**: 获取当前用于注册的临时RSA公钥

#### 请求参数

无

#### 响应参数

| 参数名     | 类型   | 描述                       |
| ---------- | ------ | -------------------------- |
| public_key | String | Base64编码的当前RSA公钥    |
| expires_in | Long   | 公钥有效期（秒）           |
| algorithm  | String | 加密算法，固定为"RSA-OAEP" |

#### 响应示例

```json
{
  "public_key": "Base64编码的RSA公钥",
  "expires_in": 259200,
  "algorithm": "RSA-OAEP"
}
```

#### 内部处理流程

1. **获取当前公钥**: 从临时密钥服务获取当前RSA公钥
2. **Base64编码**: 将公钥编码为Base64字符串
3. **计算有效期**: 获取密钥轮换周期作为有效期
4. **返回响应**: 返回公钥、有效期和算法信息

#### 错误响应

| 状态码 | 错误信息                 | 描述         |
| ------ | ------------------------ | ------------ |
| 500    | Failed to get public key | 获取公钥失败 |

---

### 4. 种子恢复

**端点**: `POST /api/v1/seed/recover`

**描述**: 恢复用户种子密钥

#### 请求参数

| 参数名         | 类型   | 必需 | 描述                             |
| -------------- | ------ | ---- | -------------------------------- |
| user_id        | String | 是   | 用户唯一标识符                   |
| auth_proof     | String | 是   | 用户身份验证凭证（签名的时间戳） |
| client_pub_key | String | 是   | 用户公钥（用于验证身份）         |

#### 请求示例

```json
{
  "user_id": "user123",
  "auth_proof": "Base64编码的签名验证凭证",
  "client_pub_key": "Base64编码的用户公钥"
}
```

#### 响应参数

| 参数名           | 类型   | 描述                            |
| ---------------- | ------ | ------------------------------- |
| status           | String | 恢复状态，"success"表示成功     |
| encrypted_seed   | String | Base64编码的加密新种子          |
| recovery_receipt | String | Base64编码的恢复凭证（HSM签名） |

#### 响应示例

```json
{
  "status": "success",
  "encrypted_seed": "Base64编码的加密新种子",
  "recovery_receipt": "Base64编码的恢复凭证"
}
```

#### 内部处理流程

1. **用户验证**: 验证用户是否存在
2. **身份验证**: 验证用户身份
   - 解码auth_proof签名
   - 使用客户端公钥验证用户ID的签名
3. **生成新种子**: 生成新的HMAC种子
4. **种子加密**: 使用用户公钥加密新种子
5. **数据库更新**: 更新数据库中的加密种子
6. **生成恢复凭证**: 使用HSM根私钥签名恢复数据
7. **审计日志**: 记录种子恢复操作（可选）
8. **返回响应**: 返回加密的新种子和恢复凭证

#### 错误响应

| 状态码 | 错误信息                                  | 描述                 |
| ------ | ----------------------------------------- | -------------------- |
| 400    | Missing required fields for seed recovery | 缺少种子恢复必需字段 |
| 401    | Identity verification failed              | 身份验证失败         |
| 404    | User not found                            | 用户不存在           |
| 500    | Seed recovery failed                      | 种子恢复失败         |

---

### 5. 种子更换

**端点**: `POST /api/v1/seed/change`

**描述**: 更换用户种子密钥

#### 请求参数

| 参数名             | 类型   | 必需 | 描述               |
| ------------------ | ------ | ---- | ------------------ |
| user_id            | String | 是   | 用户唯一标识符     |
| old_auth_code      | String | 是   | 旧种子生成的验证码 |
| new_encrypted_seed | String | 是   | 客户端加密的新种子 |

#### 请求示例

```json
{
  "user_id": "user123",
  "old_auth_code": "Base64编码的旧种子验证码",
  "new_encrypted_seed": "Base64编码的加密新种子"
}
```

#### 响应参数

| 参数名  | 类型   | 描述                        |
| ------- | ------ | --------------------------- |
| status  | String | 更换状态，"success"表示成功 |
| message | String | 操作结果消息                |

#### 响应示例

```json
{
  "status": "success",
  "message": "Seed updated successfully"
}
```

#### 内部处理流程

1. **用户验证**: 获取用户密钥库，验证用户存在
2. **旧种子解密**: 解密数据库中的旧种子
3. **验证码验证**: 验证旧种子生成的HMAC验证码
4. **新种子解密**: 使用临时密钥服务解密客户端发送的新种子
5. **数据库更新**: 加密新种子并更新数据库
6. **返回响应**: 返回操作结果

#### 错误响应

| 状态码 | 错误信息                                | 描述                 |
| ------ | --------------------------------------- | -------------------- |
| 400    | Missing required fields for seed change | 缺少种子更换必需字段 |
| 403    | Invalid old seed verification code      | 旧种子验证码无效     |
| 404    | User not found                          | 用户不存在           |
| 500    | Seed change failed                      | 种子更换失败         |

---

### 6. 获取用户公钥

**端点**: `GET /api/v1/public-key`

**描述**: 获取指定用户的公钥

#### 请求参数

| 参数名 | 类型   | 必需 | 描述                       |
| ------ | ------ | ---- | -------------------------- |
| userId | String | 是   | 用户唯一标识符（查询参数） |

#### 请求示例

```
GET /api/v1/public-key?userId=user123
```

#### 响应参数

| 参数名     | 类型   | 描述                        |
| ---------- | ------ | --------------------------- |
| status     | String | 查询状态，"success"表示成功 |
| user_id    | String | 用户ID                      |
| public_key | String | Base64编码的用户公钥        |

#### 响应示例

```json
{
  "status": "success",
  "user_id": "user123",
  "public_key": "Base64编码的用户公钥"
}
```

#### 内部处理流程

1. **参数验证**: 验证用户ID是否为空
2. **数据库查询**: 从数据库查询用户公钥
3. **返回响应**: 返回查询结果

#### 错误响应

| 状态码 | 错误信息                                   | 描述                   |
| ------ | ------------------------------------------ | ---------------------- |
| 400    | User ID is required                        | 用户ID是必需的         |
| 404    | User not found or public key not available | 用户不存在或公钥不可用 |
| 500    | Failed to retrieve public key              | 获取公钥失败           |

---

## 健康检查API

### 1. 基础健康检查

**端点**: `GET /health`

**描述**: 基础健康检查，返回服务状态

#### 响应参数

| 参数名    | 类型   | 描述                   |
| --------- | ------ | ---------------------- |
| status    | String | 服务状态，"UP"表示正常 |
| service   | String | 服务名称               |
| version   | String | 服务版本               |
| timestamp | Long   | 当前时间戳（毫秒）     |

#### 响应示例

```json
{
  "status": "UP",
  "service": "Distributed Trustless Notary Service",
  "version": "0.1.0",
  "timestamp": 1703123456789
}
```

---

### 2. 存活检查

**端点**: `GET /health/liveness`

**描述**: 简单的存活检查，确认服务进程是否运行

#### 响应参数

| 参数名    | 类型   | 描述                      |
| --------- | ------ | ------------------------- |
| status    | String | 存活状态，"ALIVE"表示存活 |
| timestamp | Long   | 当前时间戳（毫秒）        |

#### 响应示例

```json
{
  "status": "ALIVE",
  "timestamp": 1703123456789
}
```

---

### 3. 就绪检查

**端点**: `GET /health/readiness`

**描述**: 检查服务依赖是否就绪（数据库和Redis连接）

#### 响应参数

| 参数名    | 类型   | 描述                                        |
| --------- | ------ | ------------------------------------------- |
| status    | String | 就绪状态，"READY"或"NOT_READY"              |
| database  | String | 数据库连接状态，"CONNECTED"或"DISCONNECTED" |
| redis     | String | Redis连接状态，"CONNECTED"或"DISCONNECTED"  |
| timestamp | Long   | 当前时间戳（毫秒）                          |

#### 响应示例

```json
{
  "status": "READY",
  "database": "CONNECTED",
  "redis": "CONNECTED",
  "timestamp": 1703123456789
}
```

---

### 4. 详细健康检查

**端点**: `GET /health/detailed`

**描述**: 详细的健康检查，包含系统和环境信息

#### 响应参数

| 参数名                      | 类型    | 描述                   |
| --------------------------- | ------- | ---------------------- |
| status                      | String  | 服务状态，"UP"表示正常 |
| service                     | String  | 服务名称               |
| version                     | String  | 服务版本               |
| build                       | String  | 构建日期               |
| environment                 | String  | 运行环境               |
| system                      | Object  | 系统信息               |
| system.java_version         | String  | Java版本               |
| system.available_processors | Integer | 可用处理器数量         |
| system.free_memory          | Long    | 空闲内存（字节）       |
| system.total_memory         | Long    | 总内存（字节）         |
| system.max_memory           | Long    | 最大内存（字节）       |
| timestamp                   | Long    | 当前时间戳（毫秒）     |

#### 响应示例

```json
{
  "status": "UP",
  "service": "Distributed Trustless Notary Service",
  "version": "0.1.0",
  "build": "2025-12-10",
  "environment": "development",
  "system": {
    "java_version": "17.0.2",
    "available_processors": 8,
    "free_memory": 134217728,
    "total_memory": 268435456,
    "max_memory": 4294967296
  },
  "timestamp": 1703123456789
}
```

---

## 配置参数

### 系统配置

| 参数名         | 默认值                                     | 描述          |
| -------------- | ------------------------------------------ | ------------- |
| NOTARY_PORT    | 8080                                       | 服务端口      |
| DB_URL         | jdbc:postgresql://localhost:5432/notary_db | 数据库连接URL |
| DB_USER        | notary_user                                | 数据库用户名  |
| DB_PASSWORD    | 123456                                     | 数据库密码    |
| REDIS_HOST     | localhost                                  | Redis主机地址 |
| REDIS_PORT     | 6379                                       | Redis端口     |
| REDIS_PASSWORD | ""                                         | Redis密码     |

### 安全配置

| 参数名                       | 默认值 | 描述              |
| ---------------------------- | ------ | ----------------- |
| ephemeralKeyRotationInterval | 3天    | 临时密钥轮换周期  |
| replayTtl                    | 300秒  | 防重放缓存时间    |
| tsaToleranceSeconds          | 90秒   | TSA时间容忍度     |
| tsaMaxAgeSeconds             | 300秒  | TSA令牌最大有效期 |

---

## 错误处理

### 通用错误格式

所有API错误响应都遵循统一格式：

```json
{
  "error": "错误描述信息",
  "status": "error"
}
```

### HTTP状态码

| 状态码 | 含义                  | 描述           |
| ------ | --------------------- | -------------- |
| 200    | OK                    | 请求成功       |
| 201    | Created               | 资源创建成功   |
| 400    | Bad Request           | 请求参数错误   |
| 401    | Unauthorized          | 未授权         |
| 403    | Forbidden             | 禁止访问       |
| 404    | Not Found             | 资源不存在     |
| 409    | Conflict              | 资源冲突       |
| 500    | Internal Server Error | 内部服务器错误 |
| 503    | Service Unavailable   | 服务不可用     |

---

## 安全注意事项

1. **密钥保护**: 所有密钥都使用HSM或加密存储，确保密钥安全
2. **传输安全**: 建议使用HTTPS/TLS加密传输
3. **防重放**: 使用Redis存储请求指纹，防止重复请求
4. **时间验证**: 严格验证时间戳，防止重放攻击
5. **身份验证**: 使用多重验证机制确保用户身份
6. **审计日志**: 重要操作应记录审计日志
7. **密钥轮换**: 定期轮换临时密钥，提高安全性

---

## 示例代码

### 用户注册示例

```javascript
// 1. 获取注册公钥
const publicKeyResponse = await fetch('/api/v1/registration-public-key');
const { public_key } = await publicKeyResponse.json();

// 2. 准备注册数据
const userId = 'user123';
const clientSeedKey = 'my-secret-seed-key';
const payload = `${userId}|${clientSeedKey}`;

// 3. 使用公钥加密载荷
const encryptedPayload = await encryptWithPublicKey(public_key, payload);

// 4. 发送注册请求
const registerResponse = await fetch('/api/v1/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    user_id: userId,
    encrypted_payload: encryptedPayload
  })
});

const result = await registerResponse.json();
console.log('注册结果:', result);
```

### 数字签名示例

```javascript
// 1. 准备签名数据
const userId = 'user123';
const message = '这是一条需要签名的消息';
const msgHash = await sha256(message);
const clientTsMs = Date.now();

// 2. 生成HMAC授权码（详见授权码计算章节）
const authCode = await calculateAuthCode(userSeed, msgHash, clientTsMs);

// 3. 获取TSA令牌（需要与TSA服务交互）
const tsaToken = await getTsaToken(userId, msgHash, clientTsMs);

// 4. 发送签名请求
const signResponse = await fetch('/api/v1/sign', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    user_id: userId,
    msg_hash: msgHash,
    auth_code: authCode,
    client_ts_ms: clientTsMs,
    tsa_token_base64: tsaToken
  })
});

const result = await signResponse.json();
console.log('签名结果:', result);
```

### 授权码计算示例

```javascript
// 详细的授权码计算示例
async function calculateAuthCode(hmacSeed, msgHash, clientTsMs) {
    // 确保输入参数正确
    if (!hmacSeed || !msgHash || !clientTsMs) {
        throw new Error('Missing required parameters for auth code calculation');
    }
    
    // 构造消息数据：消息哈希 + 时间戳
    const messageData = msgHash + clientTsMs.toString();
    console.log('消息数据:', messageData);
    
    // 导入HMAC密钥
    const key = await crypto.subtle.importKey(
        'raw',
        hmacSeed,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // 计算HMAC签名
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(messageData)
    );
    
    // 转换为十六进制字符串
    const authCode = Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    
    console.log('计算得到的授权码:', authCode);
    return authCode;
}

// 使用示例
const userSeed = new Uint8Array([/* 32字节的HMAC种子 */]);
const messageHash = 'a1b2c3d4e5f6789'; // SHA-256哈希
const timestamp = Date.now();

const authCode = await calculateAuthCode(userSeed, messageHash, timestamp);
console.log('最终授权码:', authCode);
```

---

## 版本历史

| 版本  | 日期       | 更新内容               |
| ----- | ---------- | ---------------------- |
| 0.1.0 | 2025-12-10 | 初始版本，包含基础功能 |
| 0.1.1 | 2025-12-14 | 添加授权码计算详解章节 |

---

## 联系信息

如有问题或建议，请联系开发团队。

---

*本文档最后更新时间: 2025-12-14*