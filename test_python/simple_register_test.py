#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import requests

# API 基础 URL (根据您的实际部署修改)
BASE_URL = "http://localhost:8080"

def get_registration_public_key():
    """获取用于注册的临时公钥"""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/registration-public-key")
        response.raise_for_status()
        data = response.json()
        print("获取到的公钥信息:")
        print(f"  公钥: {data['public_key'][:50]}...")
        print(f"  算法: {data.get('algorithm', 'N/A')}")
        print(f"  过期时间(秒): {data.get('expires_in', 'N/A')}")
        return data["public_key"]
    except requests.exceptions.RequestException as e:
        print(f"获取公钥失败: {e}")
        return None

def test_register_with_mock_encryption(user_id):
    """使用模拟加密数据测试注册接口"""
    print("\n=== 测试注册接口 ===")
    
    # 模拟加密过程 (实际应用中需要使用真实的 RSA 加密)
    # 这里我们只是构造一个 Base64 编码的字符串作为示例
    payload = f"{user_id}|mock_client_seed_key_12345"
    print(f"原始 payload: {payload}")
    
    # 模拟加密 (实际应用中需要使用 RSA-OAEP 加密)
    mock_encrypted_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    print(f"模拟加密 payload: {mock_encrypted_payload[:50]}...")
    
    # 构造注册请求
    register_data = {
        "user_id": user_id,
        "encrypted_payload": mock_encrypted_payload
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/register",
            json=register_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"\n响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
        
        if response.status_code == 201:
            print("✅ 请求格式正确，服务器接受了请求")
            result = response.json()
            print(f"状态: {result.get('status')}")
        elif response.status_code == 400:
            print("❌ 请求格式错误或解密失败 (这是预期的，因为我们使用了模拟加密)")
        else:
            print(f"❓ 意外的响应状态码: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")

def main():
    """主函数 - 演示测试流程"""
    print("=== API 注册测试演示 ===")
    
    # 1. 获取公钥
    print("\n1. 获取注册公钥:")
    public_key = get_registration_public_key()
    
    if not public_key:
        print("无法获取公钥，请确保服务器正在运行")
        return
    
    # 2. 测试注册接口 (使用模拟加密)
    print("\n2. 测试注册接口:")
    test_user_id = "test_user_001"
    test_register_with_mock_encryption(test_user_id)
    
    # 3. 说明真实加密流程
    print("\n=== 真实加密流程说明 ===")
    print("要实现真实的注册流程，您需要:")
    print("1. 获取服务器公钥 (使用 /api/v1/registration-public-key)")
    print("2. 构造 payload: 'user_id|client_seed_key'")
    print("3. 使用 RSA-OAEP 算法加密 payload (使用服务器公钥)")
    print("4. 将加密后的数据进行 Base64 编码")
    print("5. 发送注册请求，包含 user_id 和 encrypted_payload")
    print("\n推荐使用 Python 的 cryptography 库进行 RSA 加密:")
    print("  pip install cryptography requests")

if __name__ == "__main__":
    main()