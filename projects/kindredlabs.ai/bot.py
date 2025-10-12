import os
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..','..'))
sys.path.append(project_root)
from core.bot.basebot import *
from core.config import Config
from threading import Lock
class Action:
    USERINFO='40775d7736a6202c266154f6a051fd181de0dac795'
    TASK='4051546d5f028303898d15875f5fa12e18abee15ac'
    COMPLETE_TASK='608331403cf99faee3c380fbaa70dbfb87c0e78231'
    CLAIM_REWARD='600e3bb087c8f43b884f2319e8972028fdc079d4d6'
    REGISTRY='40386a47c19c6e814260933888a8d35a4e4aa98d04'
    LOGIN='409cfb32c35ecbf802808a34c2a75efaa95619f661'

class KindredLabsBot(BaseBot):
    def _handle_response(self, response, retry_func=None) -> None:
        """处理响应状态"""
        try:
            response.raise_for_status()
            return response
        except Exception as e:
            raise Exception(f"请求过程中发生错误,{e},{response.text}")
    
    def userinfo(self):
        self.session.headers.update({
            'next-action': Action.USERINFO,
        })
        logger.info(f"账户:第{self.index}个地址,{self.wallet.address},userinfo中...")
        data = '["%s"]'%(self.account.get('idToken'))
        response = self.session.post('https://waitlist.kindredlabs.ai/dashboard', data=data)
        self._handle_response(response)
        data=json.loads('{'+response.text.split('1:{')[-1]).get('result')
        email=data.get('email')
        uid=data.get('uid')
        waitlistCode=data.get('waitlistCode')
        fragmentEssenceDetail=data.get('fragmentEssenceDetail',{})
        self.account['email']=email
        self.account['uid']=uid
        self.account['waitlistCode']=waitlistCode
        self.account.update(fragmentEssenceDetail)
        self.config.save_accounts()
        logger.success(f"账户:第{self.index}个地址,{self.wallet.address},dashboard成功")
    def tasks(self)->List[Dict]:
        try:
            self.session.headers.update({
                'next-action': Action.TASK,
            })
            logger.info(f"账户:第{self.index}个地址,{self.wallet.address},task中...")
            data = '["%s"]'%(self.account.get('idToken'))
            response = self.session.post('https://waitlist.kindredlabs.ai/dashboard', data=data)
            self._handle_response(response)
            data=json.loads('{'+response.text.split('1:{')[-1]).get('result')
            logger.success(f"账户:第{self.index}个地址,{self.wallet.address},dashboard成功")

            return data
        except Exception as e:
            logger.error(f"账户:第{self.index}个地址,{self.wallet.address},task失败,原因:{e}")
            return []
    
    def complete_task(self,task_id:str):
        self.session.headers.update({
            'next-action': Action.COMPLETE_TASK,
        })
        logger.info(f"账户:第{self.index}个地址,{self.wallet.address},complete_task中...")
        data = '["%s","%s"]'%(self.account.get('idToken'),task_id)
        response = self.session.post('https://waitlist.kindredlabs.ai/dashboard', data=data)
        self._handle_response(response)
        logger.success(f"账户:第{self.index}个地址,{self.wallet.address},complete_task成功,task_id:{task_id}")
        return data
    def complete_all_task(self):
        tasks=self.tasks()
        for task in tasks:
            if not isinstance(task,dict) and not task.get('allowToSubmit'):
                continue

            task_id=task.get('uid')
            self.complete_task(task_id)
            time.sleep(random.randint(0,2))
    # 领取奖励
    def claim_all_rewords(self):
        tasks=self.tasks()
        for task in tasks:
            if not isinstance(task,dict) and not task.get('allowToClaim'):
                continue
            task_id=task.get('uid')
            self.claim_rewards(task_id) 
            time.sleep(random.randint(0,2))
    def claim_rewards(self,task_id:str):
        try:
            self.session.headers.update({
                'next-action': Action.CLAIM_REWARD,
            })
            logger.info(f"账户:第{self.index}个地址,{self.wallet.address},claim_reward中...")
            data = '["%s","%s"]'%(self.account.get('idToken'),task_id)
            response = self.session.post('https://waitlist.kindredlabs.ai/dashboard', data=data)
            self._handle_response(response)
            logger.success(f"账户:第{self.index}个地址,{self.wallet.address},claim_reward成功")
            return data
        except Exception as e:
            logger.error(f"账户:第{self.index}个地址,{self.wallet.address},claim_reward失败,原因:{e}")
            return None
    
    def registe(self):
        if self.account.get('registed'):
            logger.info(f"账户:第{self.index}个地址,{self.wallet.address},已注册,跳过")
            return
        code_list=[i.get('waitlistCode') for i in self.config.accounts if i.get('waitlistCode')]
        if not code_list:
            code_list=[self.config.config.get('invite_code')]
        data = '[{"loginType":"metamask","token":"%s","referralCode":"%s"}]'%(self.account.get('idToken'),random.choice(code_list))
        self.session.headers.update({
            'next-action': self.config.config.get('next_action',Action.REGISTRY),
        })
        response = self.session.post('https://waitlist.kindredlabs.ai/', data=data)
        response=self._handle_response(response)
        self.account['registed']=True
        self.config.save_accounts()
        logger.success(f"账户:第{self.index}个地址,{self.wallet.address},注册成功")
    def login(self):
        
        logger.info(f"账户:第{self.index}个地址,{self.wallet.address},登录中...")
        address='0x85e23b94e7F5E9cC1fF78BCe78cfb15B81f0DF00'
        false=False
        true=True

        abi=[{"inputs":[{"internalType":"address","name":"_defaultAdmin","type":"address"},{"internalType":"contract IEntryPoint","name":"_entrypoint","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"accountAdmin","type":"address"}],"name":"AccountCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"prevURI","type":"string"},{"indexed":false,"internalType":"string","name":"newURI","type":"string"}],"name":"ContractURIUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"signer","type":"address"}],"name":"SignerAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"signer","type":"address"}],"name":"SignerRemoved","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"accountImplementation","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"contractURI","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_admin","type":"address"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"createAccount","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"entrypoint","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_start","type":"uint256"},{"internalType":"uint256","name":"_end","type":"uint256"}],"name":"getAccounts","outputs":[{"internalType":"address[]","name":"accounts","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"signer","type":"address"}],"name":"getAccountsOfSigner","outputs":[{"internalType":"address[]","name":"accounts","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_adminSigner","type":"address"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"getAddress","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getAllAccounts","outputs":[{"internalType":"address[]","name":"","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"uint256","name":"index","type":"uint256"}],"name":"getRoleMember","outputs":[{"internalType":"address","name":"member","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleMemberCount","outputs":[{"internalType":"uint256","name":"count","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRoleWithSwitch","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"}],"name":"isRegistered","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes[]","name":"data","type":"bytes[]"}],"name":"multicall","outputs":[{"internalType":"bytes[]","name":"results","type":"bytes[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_salt","type":"bytes32"}],"name":"onRegister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_signer","type":"address"},{"internalType":"bytes32","name":"_salt","type":"bytes32"}],"name":"onSignerAdded","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_signer","type":"address"},{"internalType":"bytes32","name":"_salt","type":"bytes32"}],"name":"onSignerRemoved","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_uri","type":"string"}],"name":"setContractURI","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalAccounts","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]
        contract=self.web3.eth.contract(address=address, abi=abi)
        func=contract.functions.getAddress(Web3.to_checksum_address(self.wallet.address),Web3.to_bytes(hexstr='0x'))
        address_register=func.call()
        code_list=[i.get('waitlistCode') for i in self.config.accounts if i.get('waitlistCode')]
        if not code_list:
            code_list=[self.config.config.get('invite_code')]
        params = {
            'code': random.choice(code_list),
        }
        data = '[{"loginMethod":"metamask","providerId":"%s","wallets":[{"address":"%s","walletType":"metamask"}],"address":"%s","walletType":"metamask"}]'%(address_register.lower(),address_register.lower(),address_register.lower())      
        self.session.headers.update({
            'next-action': self.config.config.get('next_action',Action.LOGIN),
        })
        response = self.session.post('https://waitlist.kindredlabs.ai/', data=data)
        response=self._handle_response(response)
        data=json.loads('{'+response.text.split('1:{')[-1])
        accessToken=data.get('result',{}).get('accessToken')
        if accessToken:
            self.account['accessToken']=accessToken
            params = {
                'key': 'AIzaSyDo2AY5W66xkgXsaPbUN64zmbECzbz0gHU',
            }

            json_data = {
                'token': accessToken,
                'returnSecureToken': True,
            }

            response = self.session.post(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken',
                params=params,
                json=json_data,
            )
            data=self._handle_response(response).json()
            idToken=data.get('idToken')
            
            if data:
                self.account.update(data)
                self.account['address_register']=address_register
                self.config.save_accounts()
                params = {
                    'key': 'AIzaSyDo2AY5W66xkgXsaPbUN64zmbECzbz0gHU',
                }

                json_data = {
                    'idToken': idToken,
                }
                response = self.session.post(
                    'https://identitytoolkit.googleapis.com/v1/accounts:lookup',
                    params=params,
                    json=json_data,
                )
                self.registe()

            else:
                logger.error(f"账户:第{self.index}个地址,{self.wallet.address},登录失败,{data}")
        else:
            logger.error(f"账户:第{self.index}个地址,{self.wallet.address},登录失败,accessToken为空")
        
    
    
class KindredLabsBotManager(BaseBotManager):
    def run_single(self,account):
        bot=KindredLabsBot(account,self.web3,self.config)
        bot.login()
        try:
            bot.userinfo()
        except Exception as e:
            logger.error(f"账户:第{bot.index}个地址,{bot.wallet.address},userinfo失败,原因:{e}")
        try:
            bot.complete_all_task()
        except Exception as e:
            logger.error(f"账户:第{bot.index}个地址,{bot.wallet.address},complete_tasks失败,原因:{e}")
        return bot
    def run(self):
        with ThreadPoolExecutor(max_workers=self.config.max_worker) as executor:
            futures = [executor.submit(self.run_single, account) for account in self.accounts]
            bot_list=[]
            for future in as_completed(futures):
                try:
                    bot=future.result()
                    bot_list.append(bot)
                except Exception as e:
                    logger.error(f"执行过程中发生错误: {e}")
            
            futures = [executor.submit(bot.claim_all_rewords()) for bot in bot_list]
    