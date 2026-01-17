#!/usr/bin/env python3
"""
Kiro CodeWhispererRuntimeService API 测试脚本
测试以下 API 的响应结构：
- ListAvailableModels
- ListAvailableSubscriptions  
- CreateSubscriptionToken
"""

import requests
import json
import sys

# API 基础 URL
# SDK 使用的 endpoint 是 https://q.us-east-1.amazonaws.com
# 但 codewhisperer 端点也应该工作
BASE_URL = "https://codewhisperer.us-east-1.amazonaws.com"
Q_BASE_URL = "https://q.us-east-1.amazonaws.com"

# 请在这里填入你的 Access Token
ACCESS_TOKEN = "aoaAAAAAGlrshs50x0CL6_dxY2IFGtph5p504T1psy2lmhCrxenO03IHpe4o1r71vBUqHGe7xcV3MY6mSRW8zkpNsBkc0:MGUCMA/OP4ypxKWFuBlvCsXR3rUi6imzOvzqRCehw7lHRiqq30qiXsz2mgpXc64fka1+jAIxAOdSOE0tgyMeHAYginufeT24ExSu4nKeZ9PW/WIslUGumE+eP/FVpuh+6yT03XB9ug"


def get_headers():
    """获取请求头"""
    return {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Kiro/1.0",
        "x-amzn-codewhisperer-optout-preference": "OPTIN"
    }


def pretty_print(title: str, response: requests.Response):
    """美化打印响应"""
    print(f"\n{'='*60}")
    print(f"📌 {title}")
    print(f"{'='*60}")
    print(f"状态码: {response.status_code}")
    print(f"响应头:")
    for key, value in response.headers.items():
        if key.lower().startswith(('x-amz', 'content-type', 'date')):
            print(f"  {key}: {value}")
    print(f"\n响应体:")
    try:
        data = response.json()
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except:
        print(response.text[:2000] if response.text else "(空)")
    print()


def test_list_available_models():
    """
    测试 ListAvailableModels API
    端点: GET /ListAvailableModels
    """
    print("\n🔍 测试 ListAvailableModels API...")
    
    url = f"{BASE_URL}/ListAvailableModels"
    # origin 必须是 AI_EDITOR
    params = {
        "origin": "AI_EDITOR",
        "maxResults": 50
    }
    
    try:
        response = requests.get(url, headers=get_headers(), params=params)
        pretty_print("ListAvailableModels 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_list_available_models_with_provider(provider: str):
    """
    测试带 modelProvider 参数的 ListAvailableModels API
    """
    print(f"\n🔍 测试 ListAvailableModels API (provider={provider})...")
    
    url = f"{BASE_URL}/ListAvailableModels"
    params = {
        "origin": "AI_EDITOR",
        "maxResults": 50,
        "modelProvider": provider
    }
    
    try:
        response = requests.get(url, headers=get_headers(), params=params)
        pretty_print(f"ListAvailableModels (provider={provider}) 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_list_available_subscriptions():
    """
    测试 ListAvailableSubscriptions API
    端点: POST /listAvailableSubscriptions
    """
    print("\n🔍 测试 ListAvailableSubscriptions API...")
    
    url = f"{BASE_URL}/listAvailableSubscriptions"
    # 这个 API 不需要参数，空 body 即可
    payload = {}
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        pretty_print("ListAvailableSubscriptions 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_create_subscription_token(subscription_type: str = None, with_client_token: bool = False, use_q_endpoint: bool = False):
    """
    测试 CreateSubscriptionToken API
    端点: POST /CreateSubscriptionToken
    
    根据源码，clientToken 是必需参数（SDK 自动生成 UUID）
    """
    import uuid
    type_str = f", type={subscription_type}" if subscription_type else ""
    token_str = ", clientToken=UUID" if with_client_token else ""
    endpoint_str = " [Q endpoint]" if use_q_endpoint else ""
    print(f"\n🔍 测试 CreateSubscriptionToken API (provider=STRIPE{type_str}{token_str}){endpoint_str}...")
    
    base = Q_BASE_URL if use_q_endpoint else BASE_URL
    url = f"{base}/CreateSubscriptionToken"
    payload = {
        "provider": "STRIPE"
    }
    if with_client_token:
        payload["clientToken"] = str(uuid.uuid4())
    if subscription_type:
        payload["subscriptionType"] = subscription_type
    
    print(f"📦 URL: {url}")
    print(f"📦 Payload: {payload}")
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        pretty_print(f"CreateSubscriptionToken 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_list_feature_evaluations():
    """
    额外测试: ListFeatureEvaluations API
    端点: POST /ListFeatureEvaluations
    """
    print("\n🔍 测试 ListFeatureEvaluations API...")
    
    url = f"{BASE_URL}/ListFeatureEvaluations"
    payload = {
        "userContext": {
            "ideCategory": "KIRO",
            "operatingSystem": "WINDOWS",
            "product": "KIRO",
            "clientId": "test-client"
        }
    }
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        pretty_print("ListFeatureEvaluations 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_update_usage_limits():
    """
    测试 UpdateUsageLimits API
    端点: POST /updateUsageLimits
    
    注意: 这个 API 可能需要管理员权限
    """
    print("\n🔍 测试 UpdateUsageLimits API...")
    
    url = f"{BASE_URL}/updateUsageLimits"
    # 根据文档尝试所有请求参数
    payload = {
        "accountId": "",
        "accountlessUserId": "",
        "directoryId": "",
        "featureType": "AGENT_TASKS",
        "justification": "Testing API",
        "permanentOverride": False,
        "requestedLimit": 1000000
    }
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        pretty_print("UpdateUsageLimits 响应", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def test_get_profile(profile_arn: str = None):
    """
    测试 GetProfile API
    端点: POST /GetProfile
    """
    print("\n🔍 测试 GetProfile API...")
    
    url = f"{BASE_URL}/GetProfile"
    # 尝试空 body 和带 profileArn
    payload = {}
    if profile_arn:
        payload["profileArn"] = profile_arn
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        pretty_print(f"GetProfile (空 body)" if not profile_arn else f"GetProfile (arn={profile_arn[:30]}...)", response)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return None


def main():
    global ACCESS_TOKEN
    
    print("=" * 60)
    print("🚀 Kiro API 测试脚本")
    print("=" * 60)
    
    # 检查 Token
    if not ACCESS_TOKEN:
        print("\n⚠️  请设置 ACCESS_TOKEN!")
        print("你可以通过以下方式获取 Token:")
        print("1. 从 Kiro Account Manager 复制账号的 Access Token")
        print("2. 或者通过命令行参数传入: python test_kiro_apis.py <token>")
        
        if len(sys.argv) > 1:
            ACCESS_TOKEN = sys.argv[1]
            print(f"\n✅ 使用命令行参数的 Token (长度: {len(ACCESS_TOKEN)})")
        else:
            return
    
    print(f"\n📡 API 基础 URL: {BASE_URL}")
    print(f"🔑 Token 长度: {len(ACCESS_TOKEN)}")
    
    # 运行测试
    print("\n" + "=" * 60)
    print("📋 开始测试...")
    print("=" * 60)
    
    # 1. ListAvailableModels
    test_list_available_models()
    
    # 2. ListAvailableModels with AMAZON provider
    test_list_available_models_with_provider("AMAZON")
    
    # 3. ListAvailableModels with ANTHROPIC provider  
    test_list_available_models_with_provider("ANTHROPIC")
    
    # 4. ListAvailableSubscriptions
    test_list_available_subscriptions()
    
    # 5. CreateSubscriptionToken
    test_create_subscription_token()  # 不带 subscriptionType
    test_create_subscription_token("KIRO_PRO")  # 带 subscriptionType (name)
    test_create_subscription_token("KIRO_PRO", with_client_token=True)  # 带 clientToken
    test_create_subscription_token("Q_DEVELOPER_STANDALONE_PRO", with_client_token=True)  # 尝试 qSubscriptionType
    test_create_subscription_token("KIRO_PRO", with_client_token=True, use_q_endpoint=True)  # 使用 Q endpoint
    
    # 6. 额外: ListFeatureEvaluations
    test_list_feature_evaluations()
    
    # 7. UpdateUsageLimits
    test_update_usage_limits()
    
    # 8. GetProfile
    test_get_profile()
    
    print("\n" + "=" * 60)
    print("✅ 测试完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
