#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
按服务端 registerUser 要求构造 payload 并做真实 RSA-OAEP 加密的 Python 测试脚本
依赖: pip install requests cryptography
"""
import base64
import json
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

BASE_URL = "http://localhost:8080"


# ---------- 工具函数 ----------
def fetch_registration_public_key() -> str | None:
    """获取注册用的临时 RSA 公钥（PEM 格式）"""
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/registration-public-key", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print("获取到的公钥信息:")
        print(f"  算法 : {data.get('algorithm', 'N/A')}")
        print(f"  过期 : {data.get('expires_in', 'N/A')} s")
        return data["public_key"]  # PEM 字符串
    except Exception as e:
        print("获取公钥失败:", e)
        return None

def build_encrypted_payload(user_id: str, client_seed_key: str, pem_public_key: str) -> str:
    """按服务端要求构造 payload 并做 RSA-OAEP 加密 -> Base64 字符串"""
    raw_payload = f"{user_id}|{client_seed_key}"
    print(f"原始 payload: {raw_payload}")

    # 如果后端给的是裸 Base64，就手动包成 PEM
    if not pem_public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        pem_public_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            + pem_public_key.strip()           # 去掉可能的多余换行
            + "\n-----END PUBLIC KEY-----"
        )

    # 加载 RSA 公钥
    public_key = serialization.load_pem_public_key(
        pem_public_key.encode("utf-8"), backend=default_backend()
    )

    # RSA-OAEP 加密 - 使用与Java端匹配的参数
    encrypted = public_key.encrypt(
        raw_payload.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_encrypted = base64.b64encode(encrypted).decode("utf-8")
    print(f"加密后 payload (Base64): {b64_encrypted[:50]}...")
    return b64_encrypted


def register_user(user_id: str, encrypted_payload: str) -> None:
    """调用 /api/v1/register"""
    body = {"user_id": user_id, "encrypted_payload": encrypted_payload}
    try:
        resp = requests.post(f"{BASE_URL}/api/v1/register",
                             json=body,
                             headers={"Content-Type": "application/json"},
                             timeout=10)
        print(f"\n响应码: {resp.status_code}")
        print("响应体:", resp.text)
        if resp.status_code == 201:
            print("✅ 注册成功")
            print("返回 JSON:", resp.json())
        else:
            print("❌ 注册失败")
    except Exception as e:
        print("请求异常:", e)


# ---------- 主流程 ----------
def main() -> None:
    print("=== 真实加密注册测试 ===")

    user_id = "test_user_001"
    client_seed_key = "client_seed_key_12345"

    # 1. 获取公钥
    pem_pk = fetch_registration_public_key()
    if not pem_pk:
        return

    # 2. 构造加密 payload
    encrypted = build_encrypted_payload(user_id, client_seed_key, pem_pk)

    # 3. 发起注册
    register_user(user_id, encrypted)


if __name__ == "__main__":
    main()