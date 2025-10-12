import os
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..','..'))
sys.path.append(project_root)
from core.bot.basebot import *
from core.config import Config
from threading import Lock
from uuid import uuid4
lock=Lock()
#实例化以上合约
class CatalystBot(BaseBot):
    def _handle_response(self, response, retry_func=None) -> None:
        """处理响应状态"""
        try:
            response.raise_for_status()
            return response
        # 抛出代理错误
        except requests.exceptions.ProxyError as e:
            logger.warning(f"代理错误,{e},重试中...")
            time.sleep(self.config.RETRY_INTERVAL)
            if retry_func:
                return retry_func()
        except Exception as e:
            raise Exception(f"请求过程中发生错误,{e},{response.text}")
    
            
    def registe(self):
        logger.info(f"账户:第{self.index}个地址,{self.wallet.address},注册中...")
        def get_nonce():
            Id=str(uuid4())
            response =self.session.get(f'https://app.dynamicauth.com/api/v0/sdk/{Id}/nonce')
            data=response.json()
            nonce=data.get('nonce')
            return nonce,Id
        def sign_nonce(nonce,Id):
            Issued_At=datetime.now().isoformat()
            json_data = {
                'signedMessage': '0x6e55129423315a87254d81445c19f5a97eef6f1358f753e5cd97afa0fe49597156336af84ce21e2baea585e25e9a098c0efaca797f23d2665aac40ff035e7e851c',
                'messageToSign': f'catalyst.caldera.xyz wants you to sign in with your Ethereum account:\n{self.wallet.address}\n\nWelcome to Catalyst by Caldera. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. Signing is a safe, gas-less transaction that does not in any way give Catalyst by Caldera permission to perform any transactions with your wallet.\n\nURI: https://catalyst.caldera.xyz/domain\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {Issued_At}\nRequest ID: {Id}',
                'publicWalletAddress': self.wallet.address,
                'chain': 'EVM',
                'walletName': 'okxwallet',
                'walletProvider': 'browserExtension',
                'network': '1',
                'additionalWalletAddresses': [],
                'sessionPublicKey': '024fcef24a06976e92daa69d659fbb0ca1f89d9416630171fe0eb532a4c57f819b',
            }

            response = self.session.post(
                'https://app.dynamicauth.com/api/v0/sdk/291cba73-d0c6-4a00-81b1-dc775eff64a1/verify',
                json=json_data,
            )
            return response
        nonce,Id=get_nonce()
        logger.info(f"nonce:{nonce},Id:{Id}")
        signature=self.wallet.sign_message(nonce)
        if not self.account.get('registed'):
            self.account['registed']=True
            self.config.save_accounts()
        self.config.save_accounts()
        data=response.json()
        token=data.get('token')
        if token:
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        
        logger.success(f"账户:第{self.index}个地址,{self.wallet.address},注册成功")
    def login(self):
        logger.info(f"账户:第{self.index}个地址,{self.wallet.address},登录中...")
        json_data = {
            'wallet': self.wallet.address,
        }
        response=self.session.post('https://mscore.onrender.com/user/login', json=json_data)
        logger.success(f"账户:第{self.index}个地址,{self.wallet.address},登录成功")
        # 登录后获取用户信息
        response=self._handle_response(response)
        data=response.json()
        token=data.get('token')
        if token:
            self.session.headers.update({'Authorization': f'Bearer {token}'})

        user=data.get('user')
        self.account.update(user)
        self.config.save_accounts()
        
    
class CatalystBotManager(BaseBotManager):
    def run_single(self,account):
        bot=CatalystBot(account,self.web3,self.config)
        bot.registe()
        bot.login()
        try:
            bot.mining()
        except Exception as e:
            logger.error(f"账户:第{bot.index}个地址,{bot.wallet.address},mining失败,原因:{e}")
        try:
            bot.check_in()
        except Exception as e:
            logger.error(f"账户:第{bot.index}个地址,{bot.wallet.address},check_in失败,原因:{e}")

        bot.claim_tasks()
       
    def run(self):
        with ThreadPoolExecutor(max_workers=self.config.max_worker) as executor:
            futures = [executor.submit(self.run_single, account) for account in self.accounts]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"执行过程中发生错误: {e}")


    