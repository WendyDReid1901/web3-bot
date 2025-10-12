import requests
from loguru import logger
import time
from functools import *
from typing import *
from urllib.parse import urlparse, parse_qs
from loguru import logger
from fake_useragent import UserAgent
from web3 import Web3
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_account.messages import encode_defunct
from threading import Lock
from functools import *
from eth_account.signers.local import LocalAccount
from apscheduler.schedulers.blocking import BlockingScheduler
from requests import Session
from curl_cffi import requests as curl_cffi_requests
import json
from email.header import decode_header
import time
from datetime import datetime

class ClaimNftBot:
    abi=json.loads('[{"inputs":[{"internalType":"address","name":"_mainContract","type":"address"},{"internalType":"uint256","name":"_startTime","type":"uint256"},{"internalType":"uint256","name":"_endTime","type":"uint256"},{"internalType":"address","name":"_validator","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"oldTolerance","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newTolerance","type":"uint256"}],"name":"TimestampToleranceUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"oldValidator","type":"address"},{"indexed":true,"internalType":"address","name":"newValidator","type":"address"}],"name":"ValidatorUpdated","type":"event"},{"inputs":[{"internalType":"address[]","name":"users","type":"address[]"}],"name":"batchMint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes","name":"signature","type":"bytes"},{"internalType":"uint256","name":"signedTimestamp","type":"uint256"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"endTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isAllMinted","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"mainContract","outputs":[{"internalType":"contract IYeti","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"remainingToMint","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"startTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"timestampTolerance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_startTime","type":"uint256"},{"internalType":"uint256","name":"_endTime","type":"uint256"}],"name":"updateClaimWindow","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_tolerance","type":"uint256"}],"name":"updateTimestampTolerance","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_validator","type":"address"}],"name":"updateValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"validator","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]')
    address='0xF415784F14593dd9987ECAcD0DBdFcD44246Bd38'
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'authorization': 'Bearer null',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://claimnft.yala.org',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://claimnft.yala.org/',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Microsoft Edge";v="138"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0',
    }
    # 2025-07-14 18:00:00时间戳
    start_time=datetime.timestamp(datetime.strptime('2025-07-14 18:00:00','%Y-%m-%d %H:%M:%S'))
    def __init__(self,web3,private_key,proxies):
        self.web3=web3
        self.proxies=proxies
        self.session=Session( )
        self.session.headers.update(self.headers)
        self.private_key=private_key
        self.wallet:LocalAccount=self.web3.eth.account.from_key(private_key)
        self.login()
    def login(self): 
        def sign_msg(private_key,msg):
            '''
            钱包签名
            '''
            # 使用web3.py编码消息
            message_encoded = encode_defunct(text=msg)
            # 签名消息
            signed_message = self.web3.eth.account.sign_message(message_encoded,private_key)
            # 打印签名的消息
            sign=signed_message.signature.hex()
            if '0x' not in sign:
                sign ='0x'+sign
            return sign
        def get_challenge():    
            data={
                'chain':1,
                'address':self.wallet.address
            }
            r=self.session.post('https://api.yala.org/api/account/challenge',json=data)
            return r.json().get('data')
        address=self.wallet.address
        challenge=get_challenge()

        json_data = {
            'address': address,
            'chain': 1,
            'expires': challenge.get('expires'),
            'hmac': challenge.get('hmac'),
            'signature': sign_msg(self.private_key,challenge.get('tips')),
        }

        response = self.session.post('https://api.yala.org/api/account/login', json=json_data)
        tokenAccess=response.json().get('data').get('tokenAccess')
        self.session.headers.update({'authorization': 'Bearer '+tokenAccess})
    def get_proof(self):
        r=self.session.get('https://api.yala.org/api/sign/proof')
        return r.json().get('data')
    def is_start(self):
        if time.time()<self.start_time:
            return False
        return True

    def claim(self):
        if not self.is_start():
            time.sleep(0.1)
            logger.warning(f'{self.wallet.address}-未开始')
            self.claim()
            return
        resp=self.get_proof()
        contract=self.web3.eth.contract(address=Web3.to_checksum_address(self.address),abi=self.abi)
        if resp.get('data'):
            logger.info(f'{self.wallet.address}-{resp.get("data")}')
            signature=resp.get('data').get('signature')
            timestamp=int(resp.get('data').get('timestamp'))
            tx=contract.functions.claim(Web3.to_bytes(hexstr=signature),Web3.to_int(timestamp)).build_transaction({
                'from':self.wallet.address,
                'nonce':self.web3.eth.get_transaction_count(self.wallet.address),
                'gas':30000,
                'gasPrice':self.web3.eth.gas_price,
            })
            signed_tx=self.web3.eth.account.sign_transaction(tx,self.private_key)
            tx_hash=self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            is_success=self.web3.eth.wait_for_transaction_receipt(tx_hash).status
            if is_success:
                logger.info(f'{self.wallet.address}-{tx_hash}')
            else:
                logger.warning(f'{self.wallet.address}-{tx_hash}')
            return self.web3.toHex(tx_hash)
        else:
            logger.warning(f'{self.wallet.address}-{resp.text}')

    
    def claim_test(self):
        signature='0x1314561423313'
        timestamp=int(time.time())
        contract=self.web3.eth.contract(address=Web3.to_checksum_address(self.address),abi=self.abi)
        tx=contract.functions.claim(Web3.to_bytes(hexstr=signature),Web3.to_int(timestamp)).build_transaction({
            'from':self.wallet.address,
            'nonce':self.web3.eth.get_transaction_count(self.wallet.address),
            'gas':30000,
            'gasPrice':self.web3.eth.gas_price,
        })
        signed_tx=self.web3.eth.account.sign_transaction(tx,self.private_key)
        tx_hash=self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return self.web3.toHex(tx_hash)
def main():
    import os,sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir))
    sys.path.append(project_root)
    rpc_url='https://cloudflare-eth.com/'
    proxies={
        'http':'http://xxx',
        'https':'http://xxx'
    }
    accounts=pd.read_csv('account.csv').to_dict(orient='records')

    web3 = Web3(Web3.HTTPProvider(rpc_url,request_kwargs={"proxies": proxies}))
    if not web3.is_connected():
        raise Exception("未连接到以太坊网络")
    pool=ThreadPoolExecutor(max_workers=10)
    for account in accounts:
        private_key=account.get('private_key')
        bot=ClaimNftBot(web3,private_key,proxies)
        pool.submit(bot.claim)
    pool.shutdown()

if __name__=='__main__':
    from apscheduler.schedulers.blocking import BlockingScheduler
    scheduler = BlockingScheduler()
    # 18:00:00
    scheduler.add_job(main, 'cron', hour=17, minute=59, second=55)

    scheduler.start()
    
