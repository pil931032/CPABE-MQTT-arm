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
from PolicyCompare import PolicyCompare
from PublishEmulation import PublishEmulation
import datetime
from obtain_params import obtain_params

class GenPolicyUpdateKey:
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
        r = requests.get('https://'+setting['ProxyIP']+':443/broker/global-parameters/'+setting['BrockerLoginUser']+'/'+setting['BrockerLoginPassword'],verify=False)
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
    
    def genpukey(self):
        dac = ABENCLWH(PairingGroup('SS512'))
        setting = self.load_setting()
        GPP,authorities = self.get_global_parameter()

    # get secret, old_shares_list and cipher_AES_Key
        pubemu = obtain_params()
        secret, old_shares_list, cipher_AES_Key = pubemu.emu()    
        CT = bytesToObject(cipher_AES_Key,PairingGroup('SS512'))

    # policy compare
        pc = PolicyCompare(PairingGroup('SS512'))
        I1,I2,I3,new_shares_list = pc.compare(secret,old_shares_list)

    # compute policy update key
        type1_UK, type2_UK_1, type2_UK_2, type3_UK_1, type3_UK_2, type3_UK_3 = [], [], [], [], [], []
        for i in I1:
            a = new_shares_list[i[0]-1][1]
            b = old_shares_list[i[1]-1][1]
            type1_UK.append(a - b) 

        for i in I2:
            a = new_shares_list[i[0]-1][1]
            b = old_shares_list[i[1]-1][1]
            type2_UK_1.append(a - b) 
            type2_UK_2.append(pc.group.random())


        new_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in new_shares_list])
        old_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in old_shares_list])

        attr_key = list(new_shares_dict)

        _, APK, authAttrs = authorities
        for i in I3:
            lambda_prime = new_shares_list[i[0]-1][1]
            attrPK = authAttrs[attr_key[i[0]-1]]
            r_i_prime = pc.group.random()
            type3_UK_1.append((GPP['g_a'] ** lambda_prime) * ~(attrPK['PK'] ** r_i_prime))
            type3_UK_2.append(APK['g_beta_inv'] ** r_i_prime)
            type3_UK_3.append(~(APK['g_beta_gamma'] ** r_i_prime))
        
        updatekeys = dict()
        updatekeys['I1'] = I1
        updatekeys['I2'] = I2
        updatekeys['I3'] = I3
        updatekeys['type1_UK'] = type1_UK
        updatekeys['type3_UK_1'] = type3_UK_1
        updatekeys['type3_UK_2'] = type3_UK_2
        updatekeys['type3_UK_3'] = type3_UK_3
        updatekeys['new_shares_dict'] = new_shares_dict
        updatekeys['old_shares_dict'] = old_shares_dict
        updatekeys['policy'] = setting['NewPolicy']

        updatekeys_bytes = objectToBytes(updatekeys,PairingGroup('SS512'))

        show_udk = updatekeys
        del show_udk['I1']
        del show_udk['I2']
        del show_udk['I3']
        print(show_udk)
        
        pukdata = {'puk' : updatekeys_bytes}
        rpuk = requests.post('https://'+setting['BrockerIP']+':443/PolicyUpdateKey/', data = pukdata, verify=False)
        json_obj = json.loads(rpuk.text)


if __name__ == '__main__':
    gpuk = GenPolicyUpdateKey()
    gpuk.genpukey()