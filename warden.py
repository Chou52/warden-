import requests
import json
import time
import random
import uuid
import string
from eth_account import Account
from eth_account.messages import encode_defunct
from concurrent.futures import ThreadPoolExecutor, as_completed

class WardenAutomation:
    def __init__(self, specified_indices=None):
        self.private_keys = self.load_private_keys()
        self.proxies = self.load_proxies()
        self.yescaptcha_key = ""  # 请替换为你的yescaptcha API密钥
        self.specified_indices = []  # 指定要运行的钱包序号列表
        self.failed_indices = []  # 记录失败的钱包序号
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
        ]
    
    def load_private_keys(self):
        """从pk.txt加载私钥"""
        try:
            with open('pk.txt', 'r', encoding='utf-8') as f:
                keys = [line.strip() for line in f.readlines() if line.strip()]
            print(f"加载了 {len(keys)} 个私钥")
            return keys
        except FileNotFoundError:
            print("未找到pk.txt文件")
            return []
    
    def load_proxies(self):
        """从ip.txt加载代理IP"""
        try:
            with open('ip.txt', 'r', encoding='utf-8') as f:
                proxy_lines = [line.strip() for line in f.readlines() if line.strip()]
            
            proxies = []
            for line in proxy_lines:
                # 格式: 账号:密码@ip:端口:代理协议
                if '@' in line:
                    auth_part, ip_part = line.split('@', 1)
                    username, password = auth_part.split(':', 1)
                    
                    # 解析IP部分
                    parts = ip_part.split(':')
                    if len(parts) >= 2:
                        ip = parts[0]
                        port = parts[1]
                        protocol = parts[2] if len(parts) > 2 else 'http'
                        
                        proxy_url = f"{protocol}://{username}:{password}@{ip}:{port}"
                        proxies.append({
                            'http': proxy_url,
                            'https': proxy_url
                        })
            
            print(f"加载了 {len(proxies)} 个代理")
            return proxies
        except FileNotFoundError:
            print("未找到ip.txt文件")
            return []
    
    def get_common_headers(self):
        """获取通用headers"""
        return {
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": self.get_random_ua()
        }
    
    def get_wallets_to_process(self):
        """获取要处理的钱包列表"""
        if self.specified_indices:
            # 验证指定的序号是否有效
            valid_indices = []
            for idx in self.specified_indices:
                if 0 <= idx < len(self.private_keys):
                    valid_indices.append(idx)
                else:
                    print(f"警告: 序号 {idx + 1} 超出范围，将被忽略")
            
            if not valid_indices:
                print("错误: 没有有效的钱包序号")
                return []
            
            print(f"指定运行钱包序号: {[i + 1 for i in valid_indices]}")
            return [(i, self.private_keys[i]) for i in valid_indices]
        else:
            # 处理所有钱包
            return [(i, pk) for i, pk in enumerate(self.private_keys)]
    
    def retry_with_delay(self, func, *args, max_retries=5, **kwargs):
        """重试机制：失败时等待随机时间重试，最多5次"""
        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                if result:  # 如果成功则返回结果
                    return result
                else:
                    if attempt < max_retries - 1:  # 不是最后一次尝试
                        delay = random.uniform(3, 8)  # 3-8秒随机延迟
                        print(f"第 {attempt + 1} 次尝试失败，等待 {delay:.1f} 秒后重试...")
                        time.sleep(delay)
                    else:
                        print(f"所有 {max_retries} 次尝试均失败")
                        return None
            except Exception as e:
                if attempt < max_retries - 1:  # 不是最后一次尝试
                    delay = random.uniform(3, 8)  # 3-8秒随机延迟
                    print(f"第 {attempt + 1} 次尝试出错: {str(e)}, 等待 {delay:.1f} 秒后重试...")
                    time.sleep(delay)
                else:
                    print(f"所有 {max_retries} 次尝试均出错，最后错误: {str(e)}")
                    return None
        return None
    
    def safe_retry_with_exit(self, task_name, func, *args, **kwargs):
        """安全重试机制：失败后返回None表示需要退出"""
        print(f"正在{task_name}...")
        result = self.retry_with_delay(func, *args, **kwargs)
        if result is None:
            print(f"{task_name}失败，停止处理该账户")
            return None
        return result
    
    def get_random_ua(self):
        """获取随机User-Agent"""
        return random.choice(self.user_agents)
    
    def solve_turnstile(self, site_key, page_url, proxy=None):
        """使用yescaptcha解决Cloudflare Turnstile"""
        try:
            # 创建任务
            create_task_url = "https://api.yescaptcha.com/createTask"
            task_data = {
                "clientKey": self.yescaptcha_key,
                "task": {
                    "type": "TurnstileTaskProxyless",
                    "websiteURL": page_url,
                    "websiteKey": site_key
                }
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(create_task_url, json=task_data, headers=headers, proxies=proxy, timeout=30)
            result = response.json()
            
            if result.get("errorId") != 0:
                print(f"创建Turnstile任务失败: {result.get('errorDescription')}")
                return None
            
            task_id = result.get("taskId")
            print(f"Turnstile任务创建成功，任务ID: {task_id}")
            
            # 等待任务完成
            get_result_url = "https://api.yescaptcha.com/getTaskResult"
            max_attempts = 60  # 最多等待5分钟
            
            for attempt in range(max_attempts):
                time.sleep(5)  # 每5秒检查一次
                
                result_data = {
                    "clientKey": self.yescaptcha_key,
                    "taskId": task_id
                }
                
                response = requests.post(get_result_url, json=result_data, headers=headers, proxies=proxy, timeout=30)
                result = response.json()
                
                if result.get("errorId") != 0:
                    print(f"获取Turnstile结果失败: {result.get('errorDescription')}")
                    return None
                
                status = result.get("status")
                if status == "ready":
                    solution = result.get("solution", {})
                    token = solution.get("token")
                    print(f"Turnstile验证成功")
                    return token
                elif status == "processing":
                    print(f"Turnstile验证中... ({attempt + 1}/{max_attempts})")
                    continue
                else:
                    print(f"Turnstile验证失败，状态: {status}")
                    return None
            
            print("Turnstile验证超时")
            return None
            
        except Exception as e:
            print(f"解决Turnstile验证时出错: {str(e)}")
            return None
    
    def get_nonce(self, address, cf_token, privy_ca_id, proxy=None):
        """获取nonce"""
        try:
            url = "https://auth.privy.io/api/v1/siwe/init"
            headers = {
                "authority": "auth.privy.io",
                "accept": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                "content-type": "application/json",
                "privy-app-id": "cm7f00k5c02tibel0m4o9tdy1",
                "privy-ca-id": privy_ca_id,
                "privy-client": "react-auth:2.13.8",
                **self.get_common_headers()
            }
            
            payload = {
                "address": address,
                "token": cf_token
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                nonce = data.get('nonce')
                print(f"获取nonce成功: {nonce}")
                return nonce
            else:
                print(f"获取nonce失败，状态码: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"获取nonce时出错: {str(e)}")
            return None
    
    def sign_message(self, private_key, message):
        """使用EIP-4361协议签名消息"""
        try:
            account = Account.from_key(private_key)
            # 使用EIP-4361标准签名（Sign-In with Ethereum）
            message_hash = encode_defunct(text=message)
            signed_message = account.sign_message(message_hash)
            # 确保签名以0x开头
            signature = signed_message.signature.hex()
            if not signature.startswith('0x'):
                signature = '0x' + signature
            print(f"签名成功")
            return signature
        except Exception as e:
            print(f"签名消息时出错: {str(e)}")
            return None
    
    def authenticate(self, message, signature, privy_ca_id, proxy=None):
        """获取认证token"""
        try:
            url = "https://auth.privy.io/api/v1/siwe/authenticate"
            headers = {
                "authority": "auth.privy.io",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                "privy-app-id": "cm7f00k5c02tibel0m4o9tdy1",
                "privy-ca-id": privy_ca_id,
                "privy-client": "react-auth:2.13.8",
                **self.get_common_headers()
            }
            
            payload = {
                "message": message,
                "signature": signature,
                "chainId": "eip155:137",
                "walletClientType": "okx_wallet",
                "connectorType": "injected",
                "mode": "login-or-sign-up"
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                privy_access_token = data.get('privy_access_token')
                
                if token:
                    print(f"获取认证token成功!")
                    if privy_access_token:
                        print(f"privy_access_token获取成功")
                    return token
                else:
                    print("响应中未找到token")
                    return None
            else:
                print(f"认证失败，状态码: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"认证时出错: {str(e)}")
            return None
    
    def set_referral_code(self, auth_token, referral_code="0PQIL", proxy=None):
        """设置邀请码"""
        try:
            url = f"https://api.app.wardenprotocol.org/api/users/me?referralCode={referral_code}"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "method": "GET",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "priority": "u=1, i",
                "referer": "https://app.wardenprotocol.org/",
                **self.get_common_headers()
            }
            
            response = requests.get(url, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code == 201:
                data = response.json()
                
                # 提取关键信息
                referral_code_response = data.get('referralCode')
                privy_id = data.get('privyId')
                user_id = data.get('id')
                
                print(f"设置邀请码成功! referralCode: {referral_code_response}")
                print(f"privyId: {privy_id}")
                print(f"id: {user_id}")
                
                return {
                    'referralCode': referral_code_response,
                    'privyId': privy_id,
                    'id': user_id
                }
            else:
                print(f"设置邀请码失败，状态码: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"设置邀请码时出错: {str(e)}")
            return None
    
    def record_login_activity(self, auth_token, proxy=None):
        """记录登录活动"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens/activity"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                "priority": "u=1, i",
                **self.get_common_headers()
            }
            
            # 生成正确的ISO 8601格式的UTC时间戳
            import datetime
            current_time = datetime.datetime.now(datetime.timezone.utc)
            timestamp = current_time.strftime('%Y-%m-%dT%H:%M:%S.') + f"{current_time.microsecond // 1000:03d}Z"
            
            payload = {
                "activityType": "LOGIN",
                "metadata": {
                    "action": "user_login",
                    "timestamp": timestamp,
                    "source": "privy"
                }
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code in [200, 201]:
                data = response.json()
                already_recorded = data.get('alreadyRecorded', False)
                
                if already_recorded:
                    print(f"登录活动记录成功! (已记录过)")
                    return True
                else:
                    activity_id = data.get('activityId')
                    if activity_id:
                        print(f"登录活动记录成功! 活动ID: {activity_id}")
                        return True
                    else:
                        print("登录活动记录失败: 响应中无活动ID")
                        return False
            else:
                print(f"记录登录活动失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"记录登录活动时出错: {str(e)}")
            return False
    
    def complete_daily_chat(self, auth_token, proxy=None):
        """完成每日聊天任务"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens/activity"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "method": "POST",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                **self.get_common_headers()
            }
            
            # 随机生成message_length (1-20)
            message_length = random.randint(1, 20)
            
            # 生成正确的ISO 8601格式的UTC时间戳
            import datetime
            current_time = datetime.datetime.now(datetime.timezone.utc)
            timestamp = current_time.strftime('%Y-%m-%dT%H:%M:%S.') + f"{current_time.microsecond // 1000:03d}Z"
            
            payload = {
                "activityType": "CHAT_INTERACTION",
                "metadata": {
                    "action": "user_chat",
                    "message_length": message_length,
                    "timestamp": timestamp
                }
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code in [200, 201]:
                data = response.json()
                activity_id = data.get('activityId')
                
                if activity_id:
                    new_token_price = data.get('newTokenPrice', 'N/A')
                    print(f"每日聊天任务完成成功! 活动ID: {activity_id}")
                    return True
                else:
                    print("每日聊天任务失败: 响应中无活动ID")
                    return False
            else:
                print(f"完成每日聊天任务失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"完成每日聊天任务时出错: {str(e)}")
            return False
    
    def complete_daily_game(self, auth_token, proxy=None):
        """完成每日游戏任务"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens/activity"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                "authorization": f"Bearer {auth_token}",
                **self.get_common_headers()
            }
            
            # 生成正确的ISO 8601格式的UTC时间戳
            import datetime
            current_time = datetime.datetime.now(datetime.timezone.utc)
            timestamp = current_time.strftime('%Y-%m-%dT%H:%M:%S.') + f"{current_time.microsecond // 1000:03d}Z"
            
            payload = {
                "activityType": "GAME_PLAY",
                "metadata": {
                    "action": "user_game",
                    "timestamp": timestamp
                }
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code in [200, 201]:
                data = response.json()
                activity_id = data.get('activityId')
                
                if activity_id:
                    new_token_price = data.get('newTokenPrice', 'N/A')
                    print(f"每日游戏任务完成成功! 活动ID: {activity_id}")
                    return True
                else:
                    print("每日游戏任务失败: 响应中无活动ID")
                    return False
            else:
                print(f"完成每日游戏任务失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"完成每日游戏任务时出错: {str(e)}")
            return False
    
    def generate_token_name(self):
        """生成随机的6位token名称"""
        # 字母a-z和数字0-9
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(6))
    
    def complete_create_token(self, auth_token, user_id, proxy=None):
        """完成创建代币任务"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "method": "POST",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                **self.get_common_headers()
            }
            
            # 生成随机的6位token名称
            token_name = self.generate_token_name()
            
            payload = {
                "userId": user_id,
                "tokenName": token_name
            }
            
            response = requests.post(url, json=payload, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code in [200, 201]:
                data = response.json()
                created_id = data.get('id')
                
                if created_id:
                    print(f"创建代币任务完成成功! 代币名称: {token_name}")
                    return True
                else:
                    print("创建代币任务失败: 响应中无ID")
                    return False
            else:
                print(f"完成创建代币任务失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"完成创建代币任务时出错: {str(e)}")
            return False
    
    def get_user_points(self, auth_token, proxy=None):
        """获取用户积分"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens/user/me"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                **self.get_common_headers()
            }
            
            response = requests.get(url, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                points_total = data.get('pointsTotal')
                
                if points_total is not None:
                    print(f"获取积分成功! 积分总数: {points_total}")
                    return points_total
                else:
                    print("获取积分失败: 响应中未找到pointsTotal字段")
                    print(f"响应数据: {json.dumps(data, indent=2, ensure_ascii=False)}")
                    return None
            else:
                print(f"获取积分失败，状态码: {response.status_code}")
                print(f"响应内容: {response.text}")
                return None
                
        except Exception as e:
            print(f"获取积分时出错: {str(e)}")
            return None
    
    def get_activity_status(self, auth_token, proxy=None):
        """获取任务完成状态"""
        try:
            url = "https://api.app.wardenprotocol.org/api/tokens/activity/status?activityTypes=CHAT_INTERACTION&activityTypes=WALLET_TRANSACTION"
            headers = {
                "authority": "api.app.wardenprotocol.org",
                "authorization": f"Bearer {auth_token}",
                "content-type": "application/json",
                "origin": "https://app.wardenprotocol.org",
                "referer": "https://app.wardenprotocol.org/",
                **self.get_common_headers()
            }
            
            response = requests.get(url, headers=headers, proxies=proxy, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # 解析任务状态
                chat_status = data.get('CHAT_INTERACTION', {})
                wallet_status = data.get('WALLET_TRANSACTION', {})
                
                chat_completed = chat_status.get('hasToday', False)
                wallet_completed = wallet_status.get('hasToday', False)
                
                print(f"每日聊天任务: {'已完成' if chat_completed else '未完成'}")
                print(f"每日交互任务: {'已完成' if wallet_completed else '未完成'}")
                
                return {
                    'chat_completed': chat_completed,
                    'wallet_completed': wallet_completed
                }
            else:
                print(f"获取任务状态失败，状态码: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"获取任务状态时出错: {str(e)}")
            return None
    
    def process_account(self, private_key, proxy, account_index):
        """处理单个账户"""
        try:
            print(f"\n=== 处理账户 {account_index + 1} ===")
            
            # 为每个账户生成新的privy-ca-id
            privy_ca_id = str(uuid.uuid4())
            print(f"生成新的会话ID: {privy_ca_id}")
            
            # 获取钱包地址
            account = Account.from_key(private_key)
            address = account.address
            print(f"钱包地址: {address}")
            
            # 1. 解决Cloudflare Turnstile验证
            cf_token = self.safe_retry_with_exit(
                "解决Cloudflare Turnstile验证",
                self.solve_turnstile,
                "0x4AAAAAAAM8ceq5KhP1uJBt",
                "https://app.wardenprotocol.org",
                proxy
            )
            if cf_token is None:
                self.failed_indices.append(account_index)
                return None
            
            # 2. 获取nonce
            nonce = self.safe_retry_with_exit(
                "获取nonce",
                self.get_nonce,
                address, cf_token, privy_ca_id, proxy
            )
            if nonce is None:
                self.failed_indices.append(account_index)
                return None
            
            # 3. 构建EIP-4361标准的签名消息
            current_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            message = f"""app.wardenprotocol.org wants you to sign in with your Ethereum account:
{address}

By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.

URI: https://app.wardenprotocol.org
Version: 1
Chain ID: 137
Nonce: {nonce}
Issued At: {current_time}
Resources:
- https://privy.io"""
            
            # 签名消息
            signature = self.safe_retry_with_exit(
                "使用EIP-4361协议签名",
                self.sign_message,
                private_key, message
            )
            if signature is None:
                self.failed_indices.append(account_index)
                return None
            
            # 验证签名格式
            if not signature.startswith('0x'):
                print("签名格式错误，缺少0x前缀，停止处理该账户")
                self.failed_indices.append(account_index)
                return None
            
            print("签名验证通过，继续获取认证token...")
            
            # 4. 获取认证token
            auth_token = self.safe_retry_with_exit(
                "获取认证token",
                self.authenticate,
                message, signature, privy_ca_id, proxy
            )
            if auth_token is None:
                self.failed_indices.append(account_index)
                return None
            
            # 5. 设置邀请码
            referral_result = self.safe_retry_with_exit(
                "设置邀请码",
                self.set_referral_code,
                auth_token, "0PQIL", proxy
            )
            if referral_result is None:
                print("邀请码设置失败，停止处理该账户")
                self.failed_indices.append(account_index)
                return None
            print("邀请码设置完成!")
            
            # 6. 记录登录活动
            login_success = self.safe_retry_with_exit(
                "记录登录活动",
                self.record_login_activity,
                auth_token, proxy
            )
            if login_success is None:
                print("记录登录活动失败，停止处理该账户")
                self.failed_indices.append(account_index)
                return None
            
            # 7. 完成每日聊天任务
            chat_success = self.safe_retry_with_exit(
                "完成每日聊天任务",
                self.complete_daily_chat,
                auth_token, proxy
            )
            if chat_success is None:
                print("每日聊天任务失败，停止处理该账户")
                self.failed_indices.append(account_index)
                return None
            
            # 8. 完成每日游戏任务
            game_success = self.safe_retry_with_exit(
                "完成每日游戏任务",
                self.complete_daily_game,
                auth_token, proxy
            )
            if game_success is None:
                print("每日游戏任务失败，停止处理该账户")
                self.failed_indices.append(account_index)
                return None
            
            # 9. 完成创建代币任务
            user_id = referral_result.get('id') if referral_result else None
            
            if user_id:
                token_success = self.safe_retry_with_exit(
                    "完成创建代币任务",
                    self.complete_create_token,
                    auth_token, user_id, proxy
                )
                if token_success is None:
                    print("创建代币任务失败，停止处理该账户")
                    self.failed_indices.append(account_index)
                    return None
            else:
                print("未获取到用户ID，跳过创建代币任务")
                token_success = False
            
            print(f"账户 {account_index + 1} 所有任务完成成功!")
            print(f"总结: 登录:{login_success}, 聊天:{chat_success}, 游戏:{game_success}, 代币:{token_success}")
            
            return {
                'address': address,
                'login_completed': login_success,
                'chat_completed': chat_success,
                'game_completed': game_success,
                'token_created': token_success,
                'referral_info': referral_result,
                'wallet_index': account_index
            }
                
        except Exception as e:
            print(f"处理账户 {account_index + 1} 时发生未预期错误: {str(e)}")
            print(f"停止处理该账户")
            self.failed_indices.append(account_index)
            return None
    
    def run(self, max_workers=3):
        """运行主程序"""
        if not self.private_keys:
            print("没有找到私钥，请检查pk.txt文件")
            return
        
        if not self.proxies:
            print("没有找到代理，请检查ip.txt文件")
            return
        
        if not self.yescaptcha_key or self.yescaptcha_key == "YOUR_YESCAPTCHA_API_KEY":
            print("请设置yescaptcha API密钥")
            return
        
        # 获取要处理的钱包列表
        wallets_to_process = self.get_wallets_to_process()
        if not wallets_to_process:
            return
        
        print(f"开始处理 {len(wallets_to_process)} 个账户...")
        
        results = []
        self.failed_indices = []  # 重置失败列表
        
        # 使用线程池处理多个账户
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for wallet_index, private_key in wallets_to_process:
                # 每个账户使用对应的代理（如果代理数量不足，则循环使用）
                proxy = self.proxies[wallet_index % len(self.proxies)] if self.proxies else None
                future = executor.submit(self.process_account, private_key, proxy, wallet_index)
                futures.append(future)
                
                # 添加随机延迟避免请求过于频繁
                time.sleep(random.uniform(1, 3))
            
            # 收集结果
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                # 失败的钱包序号已经在process_account中记录到self.failed_indices
        
        # 输出结果摘要
        print(f"\n=== 处理完成 ===")
        print(f"成功处理: {len(results)} 个账户")
        print(f"失败: {len(wallets_to_process) - len(results)} 个账户")
        
        # 打印失败的钱包序号
        if self.failed_indices:
            failed_display = [str(i + 1) for i in self.failed_indices]
            print(f"失败的钱包序号: {', '.join(failed_display)}")
            print(f"重新运行失败钱包的命令示例:")
            print(f"automation = WardenAutomation(specified_indices={self.failed_indices})")
            print(f"automation.run()")
        else:
            print("所有钱包处理成功!")
        
        # 打印每个账户的详细结果
        print(f"\n=== 详细结果 ===")
        for result in results:
            wallet_num = result['wallet_index'] + 1
            login_status = "✓" if result.get('login_completed', False) else "✗"
            chat_status = "✓" if result.get('chat_completed', False) else "✗"
            game_status = "✓" if result.get('game_completed', False) else "✗"
            token_status = "✓" if result.get('token_created', False) else "✗"
            
            print(f"钱包{wallet_num}: {result['address'][:10]}... | 登录{login_status} 聊天{chat_status} 游戏{game_status} 代币{token_status}")
        
        return results

if __name__ == "__main__":
    # 创建自动化实例
    
    # 方式1: 运行所有钱包
    automation = WardenAutomation()
    
    # 方式2: 运行指定序号的钱包（序号从0开始，但显示从1开始）
    # automation = WardenAutomation(specified_indices=[0, 2, 4])  # 运行第1、3、5个钱包
    
    # 方式3: 重新运行失败的钱包（根据上次运行结果）
    # automation = WardenAutomation(specified_indices=[1, 3])  # 重新运行第2、4个钱包
    
    # 运行程序（可以调整max_workers来控制并发数）
    automation.run(max_workers=1)