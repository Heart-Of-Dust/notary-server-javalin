#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

BASE_URL = "http://localhost:8080"

class NotaryAPITester:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
    
    def get_registration_public_key(self):
        """获取注册公钥"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/registration-public-key")
            response.raise_for_status()
            data = response.json()
            print(f"获取公钥成功: algorithm={data['algorithm']}, expires_in={data['expires_in']}s")
            return data["public_key"]
        except Exception as e:
            print(f"获取公钥失败: {e}")
            return None
    
    def build_encrypted_payload(self, user_id, client_seed_key, public_key):
        """构造加密payload"""
        try:
            # 构造原始payload
            raw_payload = f"{user_id}|{client_seed_key}"
            print(f"原始payload: {raw_payload}")
            
            # 处理公钥格式
            if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
                pem_public_key = (
                    "-----BEGIN PUBLIC KEY-----\n" +
                    public_key.strip() +
                    "\n-----END PUBLIC KEY-----"
                )
            else:
                pem_public_key = public_key
            
            # 加载RSA公钥
            public_key_obj = serialization.load_pem_public_key(
                pem_public_key.encode("utf-8"),
                backend=default_backend()
            )
            
            # RSA-OAEP加密
            encrypted = public_key_obj.encrypt(
                raw_payload.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            b64_encrypted = base64.b64encode(encrypted).decode("utf-8")
            print(f"加密成功，payload长度: {len(b64_encrypted)}")
            return b64_encrypted
            
        except Exception as e:
            print(f"加密失败: {e}")
            return None
    
    def register_user(self, user_id, client_seed_key):
        """用户注册测试"""
        print(f"\n=== 开始注册用户 {user_id} ===")
        
        # 获取公钥
        public_key = self.get_registration_public_key()
        if not public_key:
            return False
        
        # 加密payload
        encrypted_payload = self.build_encrypted_payload(user_id, client_seed_key, public_key)
        if not encrypted_payload:
            return False
        
        # 发送注册请求
        payload = {
            "user_id": user_id,
            "encrypted_payload": encrypted_payload
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/register",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"注册响应状态: {response.status_code}")
            print(f"注册响应内容: {response.text}")
            
            if response.status_code == 201:
                result = response.json()
                print("✅ 注册成功!")
                print(f"用户公钥: {result.get('user_public_key', 'N/A')}")
                print(f"根背书: {result.get('root_endorsement', 'N/A')}")
                print(f"确认签名: {result.get('confirmation_signature', 'N/A')}")
                return True
            else:
                print("❌ 注册失败")
                return False
                
        except Exception as e:
            print(f"注册请求异常: {e}")
            return False
    
    def get_user_public_key(self, user_id):
        """获取用户公钥"""
        print(f"\n=== 获取用户 {user_id} 公钥 ===")
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/public-key",
                params={"userId": user_id},
                timeout=5
            )
            
            print(f"公钥响应状态: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ 获取公钥成功: {result['public_key'][:50]}...")
                return result["public_key"]
            else:
                print(f"❌ 获取公钥失败: {response.text}")
                return None
                
        except Exception as e:
            print(f"获取公钥异常: {e}")
            return None

def main():
    """主测试函数"""
    tester = NotaryAPITester()
    
    # 测试数据
    test_users = [
        {"id": "test_user_001", "seed": "client_seed_key_12345"},
        {"id": "test_user_002", "seed": "another_seed_67890"}
    ]
    
    # 测试注册功能
    for user in test_users:
        success = tester.register_user(user["id"], user["seed"])
        if success:
            # 测试获取公钥
            tester.get_user_public_key(user["id"])
    
    print("\n=== 测试完成 ===")

if __name__ == "__main__":
    main()
