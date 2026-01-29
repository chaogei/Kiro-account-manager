#!/usr/bin/env python3
"""
测试脚本：比较 GetUsageLimits (REST JSON) 和 GetUserUsageAndLimits (CBOR) API 的区别

用法：
1. 设置环境变量 ACCESS_TOKEN 或在脚本中直接填写
2. 运行: python test_usage_api.py
"""

import requests
import json
import uuid
import sys

try:
    import cbor2
    HAS_CBOR = True
except ImportError:
    HAS_CBOR = False
    print("警告: cbor2 未安装，将跳过 CBOR API 测试")
    print("安装: pip install cbor2")

# 配置
ACCESS_TOKEN = "aoaAAAAAGl60C4ZNCC4CG_Dj5B21gx4OFvwTIoQhzF72839W08oG094YZYTVO5myKV735QugrLbC7MjeyZKeE0xGsBkc0:MGQCMANcDlPni1127DuN7uJ5g/8mSIvgmkLWFz3ylYAaSiCMjl9QIILBUBCkgV1S5r/kXgIwCdJAevOKCrOQ+ijLwPib+76+w7Q6oOWaU8k967p9olP6pdkF/fw55FU34BGrcSq7"  # 填写你的 access token，或使用环境变量
IDP = "BuilderId"  # BuilderId, Github, Google
PROFILE_ARN = ""  # 可选，格式: arn:aws:codewhisperer:us-east-1:123456789:profile/xxx

# API 端点
# 官方 Kiro IDE 使用的端点是 q.us-east-1.amazonaws.com
REST_API_BASE = "https://q.us-east-1.amazonaws.com"
# 另一个端点（旧版）
CODEWHISPERER_BASE = "https://codewhisperer.us-east-1.amazonaws.com"
# 项目中使用的 CBOR 端点
CBOR_API_BASE = "https://app.kiro.dev/service/KiroWebPortalService/operation"

# User-Agent 配置
KIRO_VERSION = "0.6.18"
MACHINE_ID = "0" * 64  # 64位十六进制，测试用


def get_user_agent(machine_id=None):
    """生成 Kiro IDE 风格的 User-Agent"""
    suffix = f"KiroIDE-{KIRO_VERSION}-{machine_id}" if machine_id else f"KiroIDE-{KIRO_VERSION}"
    return f"aws-sdk-js/1.0.18 ua/2.1 os/windows lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E {suffix}"


def get_amz_user_agent(machine_id=None):
    """生成 x-amz-user-agent"""
    suffix = f"KiroIDE {KIRO_VERSION} {machine_id}" if machine_id else f"KiroIDE-{KIRO_VERSION}"
    return f"aws-sdk-js/1.0.18 {suffix}"


def test_rest_api(access_token: str, machine_id: str = None):
    """
    测试 REST JSON API: GetUsageLimits
    这是 Kiro 官方客户端使用的 API 格式
    端点: https://q.us-east-1.amazonaws.com/getUsageLimits
    """
    print("\n" + "=" * 60)
    print("测试 REST API: GetUsageLimits (官方端点)")
    print("=" * 60)
    
    url = f"{REST_API_BASE}/getUsageLimits"
    # profileArn 用于指定订阅配置文件，格式如：arn:aws:codewhisperer:us-east-1:123456789:profile/xxx
    # 如果不传，API 会使用默认配置
    params = {
        "origin": "AI_EDITOR",
        "resourceType": "AGENTIC_REQUEST",  # 官方使用的参数
        "isEmailRequired": "true",  # 获取邮箱信息
        "profileArn": PROFILE_ARN if PROFILE_ARN else None,  # 可选
    }
    # 移除 None 值
    params = {k: v for k, v in params.items() if v is not None}
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "User-Agent": get_user_agent(machine_id),
        "x-amz-user-agent": get_amz_user_agent(machine_id),
    }
    
    print(f"\nURL: {url}")
    print(f"Method: GET")
    print(f"Params: {params}")
    print(f"Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v[:80]}..." if len(v) > 80 else f"  {k}: {v}")
    
    try:
        response = requests.get(url, params=params, headers=headers)
        print(f"\nStatus: {response.status_code}")
        print(f"Content-Type: {response.headers.get('content-type')}")
        
        if response.ok:
            data = response.json()
            print(f"\n响应数据 (JSON):")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return data
        else:
            print(f"\n错误响应:")
            print(response.text[:500])
            return None
    except Exception as e:
        print(f"\n请求失败: {e}")
        return None


def test_codewhisperer_api(access_token: str, machine_id: str = None):
    """
    测试 codewhisperer 端点: GetUsageLimits
    """
    print("\n" + "=" * 60)
    print("测试 REST API: GetUsageLimits (codewhisperer 端点)")
    print("=" * 60)
    
    url = f"{CODEWHISPERER_BASE}/getUsageLimits"
    params = {
        "origin": "AI_EDITOR",
        "resourceType": "AGENTIC_REQUEST",
        "isEmailRequired": "true",
        "profileArn": PROFILE_ARN if PROFILE_ARN else None,
    }
    params = {k: v for k, v in params.items() if v is not None}
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "User-Agent": get_user_agent(machine_id),
        "x-amz-user-agent": get_amz_user_agent(machine_id),
    }
    
    print(f"\nURL: {url}")
    print(f"Method: GET")
    print(f"Params: {params}")
    
    try:
        response = requests.get(url, params=params, headers=headers)
        print(f"\nStatus: {response.status_code}")
        print(f"Content-Type: {response.headers.get('content-type')}")
        
        if response.ok:
            data = response.json()
            print(f"\n响应数据 (JSON):")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return data
        else:
            print(f"\n错误响应:")
            print(response.text[:500])
            return None
    except Exception as e:
        print(f"\n请求失败: {e}")
        return None


def test_cbor_api(access_token: str, idp: str, machine_id: str = None):
    """
    测试 CBOR API: GetUserUsageAndLimits
    这是项目中使用的 API 格式（网页端风格）
    """
    if not HAS_CBOR:
        print("\n跳过 CBOR API 测试（cbor2 未安装）")
        return None
        
    print("\n" + "=" * 60)
    print("测试 CBOR API: GetUserUsageAndLimits")
    print("=" * 60)
    
    url = f"{CBOR_API_BASE}/GetUserUsageAndLimits"
    # 注意：CBOR API 的完整 URL 格式是 base/operation
    body = {
        "isEmailRequired": True,
        "origin": "KIRO_IDE"
    }
    
    headers = {
        "accept": "application/cbor",
        "content-type": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amz-user-agent": get_amz_user_agent(machine_id),
        "authorization": f"Bearer {access_token}",
        "cookie": f"Idp={idp}; AccessToken={access_token}"
    }
    
    print(f"\nURL: {url}")
    print(f"Method: POST")
    print(f"Headers:")
    for k, v in headers.items():
        if k == "authorization":
            print(f"  {k}: Bearer {v[7:50]}...")
        elif k == "cookie":
            print(f"  {k}: {v[:50]}...")
        else:
            print(f"  {k}: {v[:80]}..." if len(v) > 80 else f"  {k}: {v}")
    print(f"Body (CBOR): {body}")
    
    try:
        encoded_body = cbor2.dumps(body)
        response = requests.post(url, data=encoded_body, headers=headers)
        print(f"\nStatus: {response.status_code}")
        print(f"Content-Type: {response.headers.get('content-type')}")
        
        if response.ok:
            data = cbor2.loads(response.content)
            print(f"\n响应数据 (CBOR decoded):")
            print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
            return data
        else:
            print(f"\n错误响应:")
            try:
                error_data = cbor2.loads(response.content)
                print(json.dumps(error_data, indent=2, ensure_ascii=False, default=str))
            except:
                print(response.text[:500])
            return None
    except Exception as e:
        print(f"\n请求失败: {e}")
        return None


def compare_responses(rest_data, cbor_data):
    """比较两个 API 的响应差异"""
    print("\n" + "=" * 60)
    print("API 响应对比")
    print("=" * 60)
    
    if not rest_data and not cbor_data:
        print("两个 API 都失败，无法比较")
        return
    
    print("\n字段对比:")
    print("-" * 40)
    
    rest_keys = set(rest_data.keys()) if rest_data else set()
    cbor_keys = set(cbor_data.keys()) if cbor_data else set()
    
    all_keys = rest_keys | cbor_keys
    
    print(f"{'字段':<30} {'REST API':<15} {'CBOR API':<15}")
    print("-" * 60)
    
    for key in sorted(all_keys):
        rest_has = "✓" if key in rest_keys else "✗"
        cbor_has = "✓" if key in cbor_keys else "✗"
        print(f"{key:<30} {rest_has:<15} {cbor_has:<15}")
    
    print("\n主要差异:")
    print("-" * 40)
    
    # REST 独有字段
    rest_only = rest_keys - cbor_keys
    if rest_only:
        print(f"REST API 独有字段: {rest_only}")
    
    # CBOR 独有字段
    cbor_only = cbor_keys - rest_keys
    if cbor_only:
        print(f"CBOR API 独有字段: {cbor_only}")
    
    # 共有字段值对比
    common_keys = rest_keys & cbor_keys
    if common_keys:
        print("\n共有字段值对比:")
        for key in sorted(common_keys):
            rest_val = rest_data.get(key)
            cbor_val = cbor_data.get(key)
            if rest_val != cbor_val:
                print(f"  {key}:")
                print(f"    REST: {rest_val}")
                print(f"    CBOR: {cbor_val}")


def main():
    import os
    
    # 获取 access token
    token = ACCESS_TOKEN or os.environ.get("ACCESS_TOKEN")
    if not token:
        print("错误: 请设置 ACCESS_TOKEN 环境变量或在脚本中填写")
        print("用法: ACCESS_TOKEN=your_token python test_usage_api.py")
        sys.exit(1)
    
    print("=" * 60)
    print("Kiro Usage API 对比测试")
    print("=" * 60)
    print(f"Machine ID: {MACHINE_ID[:16]}...")
    print(f"IDP: {IDP}")
    
    # 测试 REST API - q.us-east-1 端点 (官方客户端风格)
    rest_data = test_rest_api(token, MACHINE_ID)
    
    # 测试 REST API - codewhisperer 端点
    cw_data = test_codewhisperer_api(token, MACHINE_ID)
    
    # 测试 CBOR API (网页端风格)
    cbor_data = test_cbor_api(token, IDP, MACHINE_ID)
    
    # 对比响应
    print("\n" + "=" * 60)
    print("对比: q.us-east-1 vs CBOR")
    compare_responses(rest_data, cbor_data)
    
    print("\n" + "=" * 60)
    print("对比: codewhisperer vs CBOR")
    compare_responses(cw_data, cbor_data)
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
