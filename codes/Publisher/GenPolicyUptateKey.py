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

# class GenPolicyUpdateKey:
#     def load_setting(self):
#         with open('setting.yaml', 'r') as f:
#             return yaml.safe_load(f)
        
#     def get_global_parameter(self):
#         """
#         return GPP, authority
#         """
#         warnings.filterwarnings("ignore")
#         # Load server ip
#         setting = self.load_setting()
#         # Receice global parameters
#         r = requests.get('https://'+setting['ProxyIP']+':443/broker/global-parameters/'+setting['BrockerLoginUser']+'/'+setting['BrockerLoginPassword'],verify=False)
#         json_obj = json.loads(r.text)
#         GPP = bytesToObject(json_obj['GPP'], PairingGroup('SS512'))
#         authority = bytesToObject(json_obj['authority'], PairingGroup('SS512'))
#         # Create GPP H function
#         groupObj = PairingGroup('SS512')
#         dac = ABENCLWH(groupObj)
#         temp_GPP, temp_GMK = dac.setup()
#         GPP['H']= temp_GPP['H']
#         # Retrun
#         return (GPP,tuple(authority))
    
#     def genpukey(self):
#         dac = ABENCLWH(PairingGroup('SS512'))

#         setting = self.load_setting()
#         policy_str = setting['Policy']

#         GPP,authorities = self.get_global_parameter()


#         secret=CT_with_secret.pop('secret')
#         old_shares_list = CT_with_secret.pop('old_shares')

#         pc = PolicyCompare(PairingGroup('SS512'))
#         I1,I2,I3,new_shares_list = pc.compare(secret,old_shares_list)
#         type1_UK, type2_UK_1, type2_UK_2, type3_UK_1, type3_UK_2, type3_UK_3 = [], [], [], [], [], []
#         for i in I1:
#             a = new_shares_list[i[0]-1][1]
#             b = old_shares_list[i[1]-1][1]
#             type1_UK.append(a - b) 
#         # print("type1_UK ", type1_UK)
        
#         for i in I2:
#             a = new_shares_list[i[0]-1][1]
#             b = old_shares_list[i[1]-1][1]
#             type2_UK_1.append(a - b) 
#             type2_UK_2.append(pc.group.random())
#         # print("type2_UK_1 ", type2_UK_1)
#         # print("type2_UK_2 ", type2_UK_2)


#         new_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in new_shares_list])
#         old_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in old_shares_list])
#         attr_key = list(new_shares_dict)
#         # print(attr_key)
#         _, APK, authAttrs = authorities
#         for i in I3:
#             lambda_prime = new_shares_list[i[0]-1][1]
            
#             attrPK = authAttrs[attr_key[i[0]-1]]
#             r_i_prime = pc.group.random()
#             type3_UK_1.append((GPP['g_a'] ** lambda_prime) * ~(attrPK['PK'] ** r_i_prime))
#             type3_UK_2.append(APK['g_beta_inv'] ** r_i_prime)
#             type3_UK_3.append(~(APK['g_beta_gamma'] ** r_i_prime))
#         # print("type3_UK_1", type3_UK_1)
#         # print("type3_UK_2", type3_UK_2)
#         # print("type3_UK_3", type3_UK_3)
#         # print("\n")
#         # print(CT)
#         list_new = list(new_shares_dict)
#         list_old = list(old_shares_dict)
        
#         for i, j in zip(I1, type1_UK):
#             # print(list_old[i[1]-1],"before update:")
#             # print(CT['C'][list_old[i[1]-1]])  #print parameter 'C' before updation
#             CT['C'][list_old[i[1]-1]] = CT['C'][list_old[i[1]-1]] * (GPP['g_a'] ** j) #update parameter 'C'
#             # print(list_old[i[1]-1],"after update:")
#             # print(CT['C'][list_old[i[1]-1]],"\n")  #print parameter 'C' after updation
#         # print(CT)

#         for i, j1, j2, j3 in zip(I3, type3_UK_1, type3_UK_2, type3_UK_3):
#             # print(list_new[i[0]-1])
#             CT['C'][list_new[i[0]-1]] = j1
#             CT['D'][list_new[i[0]-1]] = j2
#             CT['DS'][list_new[i[0]-1]] = j3
#         # print(CT)

