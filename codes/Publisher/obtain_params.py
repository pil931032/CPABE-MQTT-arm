import yaml
import time
from abenc_lwh import ABENCLWH
import json
from gpiozero import CPUTemperature
import psutil
from StringEncode import StringEncode
from Encryption import Encryption
from datetime import timezone
import datetime
import warnings
import requests
from Render import Render

class obtain_params:
    def __init__(self):
        warnings.filterwarnings("ignore")
        # Timec message
        utc_time = datetime.datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
        self.message = dict()
        self.message['From'] = 'Publisher-0001-3A+'
        self.message['UTC-Time'] = utc_time.timestamp()

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def emu(self):
        setting = self.load_setting()
    
    # gathering device status data
        cpu = CPUTemperature()
        string_encode = StringEncode()
        plain_text_message = dict()
        plain_text_message['CPU_Temperature'] = cpu.temperature
        plain_text_message['CPU_Usage'] = psutil.cpu_percent()
        plain_text_message['RAM_Usage'] = psutil.virtual_memory().percent   
        plain_text = json.dumps(plain_text_message)    

    # encrypted data
        encryption = Encryption()
        cipher_AES_Key,cipher_text,policy,secret,old_shares_list = encryption.encrypt(plain_text) #add return policy
        self.message['policy']=policy  #return policy
        self.message['Cipher_AES_Key'] = cipher_AES_Key
        self.message['Cipher_Text'] = cipher_text

    # send encrypted message to broker
        EncM = {'encm' : cipher_text}
        rCT = requests.post('https://'+setting['BrockerIP']+':443/EncMessage/', data = EncM, verify=False)
        json_obj = json.loads(rCT.text)

        return (secret,old_shares_list,cipher_AES_Key)

if __name__ == '__main__':
    pubemu = obtain_params()
    pubemu.emu()