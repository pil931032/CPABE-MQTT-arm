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

class KWSearch:
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
        
    def searching():
        dac = ABENCLWH(PairingGroup('SS512'))
        with open("cipher_key.yaml") as stream:
            try:
                cipher_key = yaml.safe_load(stream)
                # print(CT)
            except yaml.YAMLError as exc:
                print(exc)
        CT =  bytesToObject(cipher_key,PairingGroup('SS512'))

        # kwsearch = KWSearch()
        T1, T3, T5 = kwsearch.trapdoor_generation()
        # print(CT['C2'], T1)
        left = pair(CT['C2'], T1)

        rho3 = dac.group.random()
        right_tmp = rho3 - rho3

        for i, j in zip(CT['I_hat'], T5):
            right_tmp = right_tmp + i * j  
        right = CT['E'] ** (T3 * right_tmp)
        
        print("left:  ", left)
        print("right: ", right)
        if left == right:
            print("left = right")



if __name__ == '__main__':
    kwsearch = KWSearch()
    KWSearch.searching()
