#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# API 基础 URL (根据您的实际部署修改)
BASE_URL = "http://localhost:8080"

def get_registration_public_key():
    """获取用于注册的临时公钥"""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/registration-public-key")
        response.raise_for_status()
        data = response.json()
        return data["public_key"]
    except requests.exceptions.RequestException as e:
        print(f"获取公钥失败: {e}")
        return None

def encrypt_payload(public_key_b64, payload):
    """使用公钥加密 payload"""
    try:
        # 解码 Base64 公钥
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = serialization.load_der_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        
        # 加密 payload
        encrypted = public_key.encrypt(
            payload.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 返回 Base64 编码的加密数据
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"加密失败: {e}")
        return None

def register_user(user_id, client_seed_key):
    """注册用户"""
    # 1. 获取公钥
    print("正在获取注册公钥...")
    public_key = get_registration_public_key()
    if not public_key:
        return None
    
    # 2. 构造 payload (格式: user_id|client_seed_key)
    payload = f"{user_id}|{client_seed_key}"
    print(f"构造的 payload: {payload}")
    
    # 3. 加密 payload
    print("正在加密 payload...")
    encrypted_payload = encrypt_payload(public_key, payload)
    if not encrypted_payload:
        return None
    
    # 4. 发送注册请求
    print("正在发送注册请求...")
    register_data = {
        "user_id": user_id,
        "encrypted_payload": encrypted_payload
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/register",
            json=register_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
        
        if response.status_code == 201:
            print("用户注册成功!")
            return response.json()
        else:
            print("用户注册失败!")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return None

def main():
    """主函数 - 测试注册流程"""
    print("=== API 注册测试 ===")
    
    # 测试参数
    user_id = "test_user_001"
    client_seed_key = "my_secret_seed_key_12345"
    
    print(f"测试用户ID: {user_id}")
    print(f"客户端种子密钥: {client_seed_key}")
    print("-" * 40)
    
    # 执行注册
    result = register_user(user_id, client_seed_key)
    
    if result:
        print("\n=== 注册结果 ===")
        print(f"状态: {result.get('status')}")
        print(f"用户公钥: {result.get('user_public_key')}")
        print(f"根背书: {result.get('root_endorsement')}")
        print(f"确认签名: {result.get('confirmation_signature')}")
    else:
        print("\n注册失败，请检查错误信息")

if __name__ == "__main__":
    main()