from core.utils import *
from core.config import Config
from curl_cffi.requests import Session
class BaseBot():
    headers={
        'Accept': 'application/json, text/plain, */*',
    }
    
    def __init__(self,account,web3,config:Config):
        self.account=account
        self.proxies = {
            "http": config.proxy,
            "https": config.proxy,
        }
        self.headers=getattr(config,'headers',{})
        self.web3 = web3
        self.RETRY_INTERVAL=config.RETRY_INTERVAL
        self.chain_id = config.chain_id
        self.session=Session(
            proxies=self.proxies,
            headers=self.headers,
            impersonate="safari17_2_ios",
            verify=False,
            timeout=600
        )
        self.account=account
        self.config:Config=config
        self.session=create_retry_session(self.session,self.config.config.get('RETRY_COUNT',3),self.config.config.get('RETRY_INTERVAL',1))
        self.wallet:LocalAccount=self.web3.eth.account.from_key(self.account.get("private_key"))
        if self.account.get('address')!=self.wallet.address or not self.account.get('address'):
            self.account['address']=self.wallet.address
            self.config.save_accounts()
        try:
            self.index=self.config.accounts.index(account)
        except:
            self.index=0
    def get_new_session(self):
        session=Session(
            proxies=self.proxies,
            impersonate="safari17_2_ios",
            verify=False,
            timeout=600
        )
        return session
    def _handle_response(self, response: requests.Response, retry_func=None) -> None:
        """处理响应状态"""
        try:
            response.raise_for_status()
            data=response.json()
            if data.get('code')!=200:
                raise Exception(f"执行异常,{data.get('msg')}")
            return data
        # 抛出代理错误
        except requests.exceptions.ProxyError as e:
            logger.warning(f"代理错误,{e},重试中...")
            time.sleep(self.config.RETRY_INTERVAL)
            if retry_func:
                return retry_func()
        except Exception as e:
            raise Exception(f"请求过程中发生错误,{e},{response.text}")
        
class BaseBotManager():
    def __init__(self,config_path:str):
        self.config=Config(config_path)
        self.accounts=self.config.accounts
        if self.config.config.get('rpc_proxy'):
            self.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }
            if hasattr(self.config,'rpc_url'):
                self.web3 = Web3(Web3.HTTPProvider(self.config.rpc_url,request_kwargs={"proxies": self.proxies}))
        else:
            if hasattr(self.config,'rpc_url'):
                self.web3 = Web3(Web3.HTTPProvider(self.config.rpc_url))
            self.proxies =None
        if hasattr(self,'web3'):
            if not self.web3.is_connected():
                logger.warning("无法连接到 RPC 节点,重试中...")
                time.sleep(self.config.RETRY_INTERVAL)
                self.__init__(config_path)
    def run_single(self,account):
        pass
    def run(self):
        pass