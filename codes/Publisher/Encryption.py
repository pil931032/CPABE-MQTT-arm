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

class Encryption:
    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def AES_encrypt(self,message:str,key:str):
        message = message.encode("utf-8")
        key = key.encode("utf-8")

        shavalue = hashlib.sha256()
        shavalue.update(key)
        key= shavalue.digest()

        cipher = AES.new(key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(message)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'nonce':nonce, 'ciphertext':ct})
        return result 

    def AES_decrypt(self,cipher_text:str,key:str):
        key = key.encode("utf-8")
        shavalue = hashlib.sha256()
        shavalue.update(key)
        key= shavalue.digest()
        try:
            b64 = json.loads(cipher_text)
            nonce = b64decode(b64['nonce'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ct)
            return pt.decode('utf-8')
        except (ValueError, KeyError):
            print("Incorrect decryption")

    def generate_AES_Key(self):
        pass

    def get_global_parameter(self):
        """
        return GPP, authority
        """
        warnings.filterwarnings("ignore")
        # Load server ip
        setting = self.load_setting()
        # Receice global parameters
        r = requests.get('https://'+setting['BrockerIP']+':443/broker/global-parameters/'+setting['BrockerLoginUser']+'/'+setting['BrockerLoginPassword'],verify=False)
        json_obj = json.loads(r.text)
        GPP = bytesToObject(json_obj['GPP'], PairingGroup('SS512'))
        authority = bytesToObject(json_obj['authority'], PairingGroup('SS512'))
        # Create GPP H function
        groupObj = PairingGroup('SS512')
        dac = DACMACS(groupObj)
        temp_GPP, temp_GMK = dac.setup()
        GPP['H']= temp_GPP['H']
        # Retrun
        return (GPP,tuple(authority))

    def encrypt(self,message:str):
        dac = DACMACS(PairingGroup('SS512'))
        string_encode = StringEncode()
        message_int:int = string_encode.string_to_integer(message)
        # Load server ip
        setting = self.load_setting()
        policy_str = setting['Policy']

        GPP,authorities = self.get_global_parameter()

        # Generate A String for AES Key
        AES_key_before_serialization  = PairingGroup('SS512').random(GT)
        AES_Key_base64_utf8 = objectToBytes(AES_key_before_serialization,PairingGroup('SS512')).decode("utf-8")
        CT = dac.encrypt(GPP, policy_str, AES_key_before_serialization, authorities)
        cipher_AES_key = objectToBytes(CT, PairingGroup('SS512')).decode("utf-8")
        cipher_text = self.AES_encrypt(message,AES_Key_base64_utf8)
        # print("Origin AES Key")
        # print(AES_Key_base64_utf8)
        # Test Decode
        test_d = cipher_AES_key.encode('utf-8')
        bytesToObject(test_d,PairingGroup('SS512'))
        # print('Success!',cipher_AES_key)
        return (cipher_AES_key,cipher_text)

if __name__ == '__main__':
    encryption = Encryption()
    encryption.encrypt('123')
