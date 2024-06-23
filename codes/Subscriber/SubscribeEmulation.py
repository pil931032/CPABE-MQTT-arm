from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS
from charm.core.engine.util import objectToBytes,bytesToObject
from StringEncode import StringEncode
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import hashlib
import yaml
import requests
import warnings
from Decryption import Decryption
from Render import Render
import datetime
from datetime import timezone
import os
from colorama import Fore, Back, Style
from abenc_lwh import ABENCLWH

class SubscribeEmulation:
    # def __init__(self):
        # Timec
        # utc_time = datetime.datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
        # self.message= dict()
        # self.message['From'] = 'Publisher-0001-3A+'
        # self.message['UTC-Time'] = utc_time.timestamp()

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def load_subscriber_user_password(self):
        with open('subscriber_user_password.yaml', 'r') as f:
            return yaml.safe_load(f)

    def get_global_parameter(self):
        """
        return GPP, authority
        """
        warnings.filterwarnings("ignore")
        # Load server ip
        setting = self.load_setting()
        # Receice global parameters
        r = requests.get('https://'+setting['BrockerIP']+':443/subscriber/global-parameters/'+setting['SubscriberLoginUser']+'/'+setting['SubscriberLoginPassword'],verify=False)
        json_obj = json.loads(r.text)
        GPP = bytesToObject(json_obj['GPP'], PairingGroup('SS512'))
        authority = bytesToObject(json_obj['authority'], PairingGroup('SS512'))
        # Create GPP H function
        groupObj = PairingGroup('SS512')
        dac = ABENCLWH(groupObj)
        temp_GPP, temp_GMK = dac.setup()
        GPP['H']= temp_GPP['H']
        # Retrun
        return (GPP,tuple(authority))

    def trapdoor_generation(self):
        dac = ABENCLWH(PairingGroup('SS512'))
        setting = self.load_setting()
        GPP,authorities = self.get_global_parameter()

        search_kw_list = setting['search_kw']
        keyword_list = setting['keyword']
        u = dac.group.random()        
        rho2 = dac.group.random()
        rho2_inv = rho2 ** (-1)
        search_kw_val_in_z_p = []
        for keyword_name in search_kw_list:
            search_kw_val = dac.group.hash(search_kw_list[keyword_name], type=ZR)
            search_kw_val_in_z_p.append(search_kw_val)
        T1 = GPP['g'] ** u
        T3 = u * rho2 * (((rho2/rho2) * len(search_kw_val_in_z_p)) ** (-1)) 
        T5 = []
        # print(search_kw_val_in_z_p)
        T5_temp = rho2 - rho2
        for l1 in range(0, len(keyword_list) + 1):    
            for i in range(0, len(search_kw_val_in_z_p) ):
                # print(i,"  ", l1)
                T5_temp = T5_temp + search_kw_val_in_z_p[i] ** (l1)
            T5.append(rho2_inv * T5_temp)
            T5_temp = rho2 - rho2
        # print(T5)
        return (T1, T3, T5)

    def searching(self):
        dac = ABENCLWH(PairingGroup('SS512'))
        setting = self.load_setting()
        T1, T3, T5 = subemu.trapdoor_generation()

        TD = {
            'T1' : T1,
            'T3' : T3,
            'T5' : T5,
        }
        BytesTD= objectToBytes(TD,PairingGroup('SS512')).decode("utf-8")
        TDdata = {'TD' : BytesTD}
        rTD = requests.post('https://'+setting['BrockerIP']+':443/SubscriberEmu/', data = TDdata, verify=False)
        json_obj = json.loads(rTD.text)

        # cipher_AES_Key = bytesToObject(json_obj['result'],PairingGroup('SS512'))
        cipher_AES_Key = json_obj['result']
        cipher_text = json_obj['result2']
        # print(cipher_text)
        # print(bytesToObject(json_obj['result'],PairingGroup('SS512')))
        # print(json_obj['result'])
        # print(CT)
        return (cipher_AES_Key, cipher_text)

    def emu(self):
        setting = self.load_setting()
        user_password = self.load_subscriber_user_password()
        # message_obj = json.loads(message_text)
    # Cipher Text

        # Cipher_AES_Key = message_obj['Cipher_AES_Key']
        # Cipher_Text = message_obj['Cipher_Text']
    # Decryption
        subemu = SubscribeEmulation()
        Cipher_AES_Key, Cipher_Text = subemu.searching()

        decryption = Decryption()
        start_decrypt_time = datetime.datetime.now()
        try:
            plain_text,user_attribute,outsourcing_total_time,local_decrypt_total_time = decryption.decryption(Cipher_AES_Key,Cipher_Text)
        except:
            os.system('clear')
            print( Fore.RED + "========= Decrypt fail =========")

        # finish_decrypt_time = datetime.datetime.now()
        # Time-consuming calculation
        # start_time = datetime.datetime.fromtimestamp(utc_time.timestamp())
        # finish_time = datetime.datetime.now()
        # total_time_string = str((finish_time - start_time).total_seconds())
        # total_decrypt_time = str((finish_decrypt_time - start_decrypt_time).total_seconds())
        # transmission_time = str((receive_time - start_time).total_seconds())
        # outsourcing_total_time = str(outsourcing_total_time.total_seconds())
        # local_decrypt_total_time =  str(local_decrypt_total_time.total_seconds())
        
    # Render
        result = json.loads(plain_text)
        render = Render()
        render.table(
            CPU_Temperature=str(result['CPU_Temperature']),
            CPU_Usage=str(result['CPU_Usage']),
            RAM_Usage=str(result['RAM_Usage']),
            Decrypted_text = json.dumps(result),
            Cipher_Key = Cipher_AES_Key,
            Cipher_Text = Cipher_Text,
            Brocker_IP = setting['BrockerIP'],
            Proxy_IP = setting['ProxyIP'],
            User = user_password['user'],
            User_ATTRIBUTE = user_attribute,

            # Decrypt_Time = total_decrypt_time,
            # Transmission_Time = transmission_time,
            # Outsourcing_Time = outsourcing_total_time,
            # Local_Decrypt_time = local_decrypt_total_time,
            # Total_Time = total_time_string,
        )

if __name__ == '__main__':
    subemu = SubscribeEmulation()
    subemu.emu()