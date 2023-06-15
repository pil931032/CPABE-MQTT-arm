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
import datetime

class Decryption:
    def __init__(self):
        warnings.filterwarnings("ignore")

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def load_subscriber_user_password(self):
        with open('subscriber_user_password.yaml', 'r') as f:
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

    def get_global_parameter(self):
        """
        return GPP, authority
        """
        # Load server ip
        setting = self.load_setting()
        user_password = self.load_subscriber_user_password()
        # Receice global parameters
        r = requests.get('https://'+setting['BrockerIP']+':443/subscriber/global-parameters/'+user_password['user']+'/'+user_password['password'], verify=False)
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

    def get_subscriber_decrypt_keys(self):
        # Load server ip
        setting = self.load_setting()
        user_password = self.load_subscriber_user_password()
        # Receice global parameters
        r = requests.get('https://'+setting['BrockerIP']+':443/subscriber/decrypt-keys/'+user_password['user']+'/'+user_password['password'], verify=False)
        obj = json.loads(r.text)
        keys = obj['decrypt-keys']
        keys = bytesToObject(keys,PairingGroup('SS512'))
        return keys

    def outsourcing(self,GPP,CT,AuthoritySecretKeys,UserKey):
        # Load server ip
        setting = self.load_setting()
        # GPP
        del GPP['H']
        GPP = objectToBytes(GPP,PairingGroup('SS512')).decode("utf-8")
        # CT
        CT= objectToBytes(CT,PairingGroup('SS512')).decode("utf-8")
        # AuthoritySecretKeys
        AuthoritySecretKeys= objectToBytes(AuthoritySecretKeys,PairingGroup('SS512')).decode("utf-8")
        # UserKey
        UserKey= objectToBytes(UserKey,PairingGroup('SS512')).decode("utf-8")
        data = {
            'GPP': GPP,
            'CT' : CT,
            'AuthoritySecretKeys' : AuthoritySecretKeys,
            'UserKey' : UserKey
        }
        r = requests.post('https://'+setting['ProxyIP']+':8080/decrypt/', data = data, verify=False)
        json_obj = json.loads(r.text)
        return bytesToObject(json_obj['result'],PairingGroup('SS512'))

    def decryption(self,cipher_key:str,cipher_text:str):
        # CPABE
        CT =  bytesToObject(cipher_key,PairingGroup('SS512'))
        dac = DACMACS(PairingGroup('SS512'))
        decryption = Decryption()
        user_key = self.get_subscriber_decrypt_keys()
        GPP,authority = self.get_global_parameter()
        # Self Decrypt
        # TK1a = dac.generateTK(GPP, CT, user_key['authoritySecretKeys'], user_key['keys'][0])
        # Outsourcing decrypt
        outsourcing_start_time = datetime.datetime.now()
        TK1a = self.outsourcing(GPP, CT, user_key['authoritySecretKeys'], user_key['keys'][0])
        outsourcing_end_time = datetime.datetime.now()
        outsourcing_total_time = outsourcing_end_time - outsourcing_start_time
        # Local decrypt
        local_decrypt_start_time = datetime.datetime.now()
        PT1a = dac.decrypt(CT, TK1a, user_key['keys'][1])
        # AES
        AES_key = objectToBytes(PT1a,PairingGroup('SS512')).decode("utf-8")
        result = self.AES_decrypt(cipher_text,AES_key)
        local_decrypt_end_time = datetime.datetime.now()
        local_decrypt_total_time = local_decrypt_end_time - local_decrypt_start_time
        # Extract User Attribute
        Attribute_AK = user_key['authoritySecretKeys']['AK']
        user_attribute = []
        for attribute in Attribute_AK:
            user_attribute.append(attribute)
        user_attribute = json.dumps(user_attribute)
        return (result,user_attribute,outsourcing_total_time,local_decrypt_total_time)


if __name__ == '__main__':
    pass