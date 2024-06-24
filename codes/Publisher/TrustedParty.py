from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from abenc_lwh import ABENCLWH
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

class TrustedParty:
    def __init__(self):
        warnings.filterwarnings("ignore")   

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

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
        dac = ABENCLWH(groupObj)
        temp_GPP, temp_GMK = dac.setup()
        GPP['H']= temp_GPP['H']
        # Retrun
        return (GPP,tuple(authority))

    def load_trusted_party_password(self):
        with open('trusted_party_password.yaml', 'r') as f:
            return yaml.safe_load(f)

    def get_trusted_party_decrypt_keys(self):
        # Load server ip
        setting = self.load_setting()
        user_password = self.load_trusted_party_password()
        # Receive global parameters
        r = requests.get('https://'+setting['BrockerIP']+':443/trusted_party/decrypt-keys/'+user_password['user']+'/'+user_password['password'], verify=False)
        obj = json.loads(r.text)
        keys = obj['decrypt-keys']
        keys = bytesToObject(keys,PairingGroup('SS512'))
        return keys 

# for ciphertext update Verification
    def sendCTUCKtoBroker(self,GPP,AuthoritySecretKeys,UserKey):
        # Load server ip
        setting = self.load_setting()
        # GPP
        del GPP['H']
        GPP = objectToBytes(GPP,PairingGroup('SS512')).decode("utf-8")
        # CT
        # CT= objectToBytes(CT,PairingGroup('SS512')).decode("utf-8")
        # AuthoritySecretKeys
        AuthoritySecretKeys= objectToBytes(AuthoritySecretKeys,PairingGroup('SS512')).decode("utf-8")
        # UserKey
        UserKey= objectToBytes(UserKey,PairingGroup('SS512')).decode("utf-8")
        data = {
            'GPP': GPP,
            # 'CT' : CT,
            'AuthoritySecretKeys' : AuthoritySecretKeys,
            'UserKey' : UserKey
        }
        r = requests.post('https://'+setting['BrockerIP']+':443/UpdateCheck/', data = data, verify=False)
        json_obj = json.loads(r.text)
        # return bytesToObject(json_obj['result'],PairingGroup('SS512'))
        return json_obj['result']

    def generate_verification_key(self):
        dac = ABENCLWH(PairingGroup('SS512'))
        string_encode = StringEncode()

        GPP,authorities = self.get_global_parameter()
        _, APK, authAttrs = authorities

        trusted_party_decrypt_key = self.get_trusted_party_decrypt_keys()
        z_0 = dac.group.random()
        z_0_inv = ~(z_0)
        CTUVK = trusted_party_decrypt_key['keys'][1] * z_0
        uvk = objectToBytes(CTUVK, PairingGroup('SS512')).decode("utf-8")
        with open('CTUVK.yaml','w') as f:
            yaml.dump(uvk, f)        

        trusted_party_decrypt_key['authoritySecretKeys']['K'] = trusted_party_decrypt_key['authoritySecretKeys']['K'] ** z_0_inv
        trusted_party_decrypt_key['authoritySecretKeys']['L'] = trusted_party_decrypt_key['authoritySecretKeys']['L'] ** z_0_inv
        trusted_party_decrypt_key['authoritySecretKeys']['R'] = trusted_party_decrypt_key['authoritySecretKeys']['R'] ** z_0_inv
        for key in trusted_party_decrypt_key['authoritySecretKeys']['AK']:
            trusted_party_decrypt_key['authoritySecretKeys']['AK'][key] = trusted_party_decrypt_key['authoritySecretKeys']['AK'][key] ** z_0_inv
        trusted_party_decrypt_key['keys'][0] = trusted_party_decrypt_key['keys'][0] ** z_0_inv

        VTK = self.sendCTUCKtoBroker(GPP,trusted_party_decrypt_key['authoritySecretKeys'], trusted_party_decrypt_key['keys'][0])
        print(VTK)
    #     VTK = self.outsourcing(GPP, CT, trusted_party_decrypt_key['authoritySecretKeys'], trusted_party_decrypt_key['keys'][0])
        
    #     # Verification
    #     egg_alpha_s = APK['e_alpha'] ** secret
    #     TKgen_result = VTK ** CTUVK
    # # print result----------------------------------------------------------------
    #     print("publisher: ", egg_alpha_s)
    #     print("broker: ", TKgen_result)
    #     if egg_alpha_s == TKgen_result:
    #         print("publisher result = broker result")

if __name__ == '__main__':
    tp = TrustedParty()
    tp.generate_verification_key()