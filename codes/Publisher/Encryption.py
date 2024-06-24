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


    def encrypt(self,message:str):
        dac = ABENCLWH(PairingGroup('SS512'))
        string_encode = StringEncode()
        message_int:int = string_encode.string_to_integer(message)
        # Load server ip
        setting = self.load_setting()
        policy_str = setting['Policy']

        GPP,authorities = self.get_global_parameter()
        _, APK, authAttrs = authorities
        # print(authorities)
        # Generate A String for AES Key
        AES_key_before_serialization = PairingGroup('SS512').random(GT)
        AES_Key_base64_utf8 = objectToBytes(AES_key_before_serialization,PairingGroup('SS512')).decode("utf-8")

        CT_with_secret = dac.encrypt(GPP, policy_str, AES_key_before_serialization, authorities)
        
        secret=CT_with_secret.pop('secret')
        old_shares_list = CT_with_secret.pop('old_shares')

        # update_data = dict(
        #     secret1 = secret,
        #     old_shares_list1 = old_shares_list
        # )
        # print(type(update_data))
        # print(update_data)
        # with open('update_data.yml', 'w') as outfile:
        #     yaml.dump(update_data, outfile, default_flow_style=False)
        # with open('update_data.yaml', 'w') as yaml_file:
        #     yaml.dump(update_data, yaml_file, default_flow_style=False)

        CT_without_secret = CT_with_secret
        CT = CT_without_secret
        # C_test = CT_without_secret['C']
        # print(CT_without_secret['C']['WORKER'])

# send CT to broker (before policy update)------------------------------------------
        BytesCT= objectToBytes(CT,PairingGroup('SS512')).decode("utf-8")
        CTdata = {'CT' : BytesCT}
        rCT = requests.post('https://'+setting['BrockerIP']+':443/Ciphertext/', data = CTdata, verify=False)
        json_obj = json.loads(rCT.text)
# ----------------------------------------------------------------------------------

   
# policy update-------------------------------------------------------------------------- -------------------------------------------------------------------------- 
#         pc = PolicyCompare(PairingGroup('SS512'))
#         I1,I2,I3,new_shares_list = pc.compare(secret,old_shares_list)        
#         type1_UK, type2_UK_1, type2_UK_2, type3_UK_1, type3_UK_2, type3_UK_3 = [], [], [], [], [], []
#         for i in I1:
#             a = new_shares_list[i[0]-1][1]
#             b = old_shares_list[i[1]-1][1]
#             type1_UK.append(a - b) 
      
#         for i in I2:
#             a = new_shares_list[i[0]-1][1]
#             b = old_shares_list[i[1]-1][1]
#             type2_UK_1.append(a - b) 
#             type2_UK_2.append(pc.group.random())

#         new_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in new_shares_list])
#         old_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in old_shares_list])
#         attr_key = list(new_shares_dict)


#         for i in I3:
#             lambda_prime = new_shares_list[i[0]-1][1]
            
#             attrPK = authAttrs[attr_key[i[0]-1]]
#             r_i_prime = pc.group.random()
#             type3_UK_1.append((GPP['g_a'] ** lambda_prime) * ~(attrPK['PK'] ** r_i_prime))
#             type3_UK_2.append(APK['g_beta_inv'] ** r_i_prime)
#             type3_UK_3.append(~(APK['g_beta_gamma'] ** r_i_prime))

#         list_new = list(new_shares_dict)
#         list_old = list(old_shares_dict)
# # type1 update --------------------------------------------------------------------------        
#         for i, j in zip(I1, type1_UK):
#             CT['C'][list_old[i[1]-1]] = CT['C'][list_old[i[1]-1]] * (GPP['g_a'] ** j) #update parameter 'C'



# # type2 update --------------------------------------------------------------------------
#         # print(CT['C'][list_new[5]])
#         # for  i, j1, j2 in zip(I2, type2_UK_1, type2_UK_2):
#         #     CT['C'][list_old[i[1]-1]] = CT['C'][list_old[i[1]-1]] * (GPP['g_a'] ** j)

# # type3 update --------------------------------------------------------------------------       
#         for i, j1, j2, j3 in zip(I3, type3_UK_1, type3_UK_2, type3_UK_3):
#             # print(list_new[i[0]-1])
#             CT['C'][list_new[i[0]-1]] = j1
#             CT['D'][list_new[i[0]-1]] = j2
#             CT['DS'][list_new[i[0]-1]] = j3

# # 'NewPolicy' update -------------------------------------------------------------------------- 
#         CT['policy'] = setting['NewPolicy']
# -------------------------------------------------------------------------- -------------------------------------------------------------------------- 
        cipher_AES_key = objectToBytes(CT, PairingGroup('SS512')).decode("utf-8")
        cipher_text = self.AES_encrypt(message,AES_Key_base64_utf8)
        # print("Origin AES Key")
        # print(AES_Key_base64_utf8)
        # Test Decode
        test_d = cipher_AES_key.encode('utf-8')
        bytesToObject(test_d,PairingGroup('SS512'))
        # print('Success!',cipher_AES_key)

# preserve eggas for ciphertext update verification by publisher
        egg_alpha_s = APK['e_alpha'] ** secret
        eggas = objectToBytes(egg_alpha_s, PairingGroup('SS512')).decode("utf-8")
        with open('eggas.yaml','w') as f:
            yaml.dump(eggas, f)   
# trapdoor------------------------------------------------
        # search_kw_list = setting['search_kw']
        # keyword_list = setting['keyword']
        # u = dac.group.random()        
        # rho2 = dac.group.random()
        # rho2_inv = rho2 ** (-1)
        # search_kw_val_in_z_p = []
        # for keyword_name in search_kw_list:
        #     search_kw_val = dac.group.hash(search_kw_list[keyword_name], type=ZR)
        #     search_kw_val_in_z_p.append(search_kw_val)
        # T1 = GPP['g'] ** u
        # T3 = u * rho2 * (((rho2/rho2) * len(search_kw_val_in_z_p)) ** (-1)) 
        # T5 = []
        # # print(search_kw_val_in_z_p)
        # T5_temp = rho2 - rho2
        # for l1 in range(0, len(keyword_list) + 1):    
        #     for i in range(0, len(search_kw_val_in_z_p) ):
        #         # print(i,"  ", l1)
        #         T5_temp = T5_temp + search_kw_val_in_z_p[i] ** (l1)
        #     T5.append(rho2_inv * T5_temp)
        #     T5_temp = rho2 - rho2
        # # print(T5)

# search test------------------------------------------------
        # # print(CT['C2'], T1)
        # left = pair(CT['C2'], T1)
        
        # right_tmp = rho2 - rho2
        # for i, j in zip(CT['I_hat'], T5):
        #     right_tmp = right_tmp + i * j  
        # right = CT['E'] ** (T3 * right_tmp)
        
        # # print("left:  ", left)
        # # print("right: ", right)
        # # if left == right:
        # #     print("left = right")
# CT Update Verification---------------------------------------
        trusted_party_decrypt_key = self.get_trusted_party_decrypt_keys()
        z_0 = dac.group.random()
        z_0_inv = ~(z_0)
        CTUVK = trusted_party_decrypt_key['keys'][1] * z_0

        trusted_party_decrypt_key['authoritySecretKeys']['K'] = trusted_party_decrypt_key['authoritySecretKeys']['K'] ** z_0_inv
        trusted_party_decrypt_key['authoritySecretKeys']['L'] = trusted_party_decrypt_key['authoritySecretKeys']['L'] ** z_0_inv
        trusted_party_decrypt_key['authoritySecretKeys']['R'] = trusted_party_decrypt_key['authoritySecretKeys']['R'] ** z_0_inv
        for key in trusted_party_decrypt_key['authoritySecretKeys']['AK']:
            trusted_party_decrypt_key['authoritySecretKeys']['AK'][key] = trusted_party_decrypt_key['authoritySecretKeys']['AK'][key] ** z_0_inv
        trusted_party_decrypt_key['keys'][0] = trusted_party_decrypt_key['keys'][0] ** z_0_inv

        VTK = self.outsourcing(GPP, CT, trusted_party_decrypt_key['authoritySecretKeys'], trusted_party_decrypt_key['keys'][0])
        
        # Verification
        # egg_alpha_s = APK['e_alpha'] ** secret
        # eggas = objectToBytes(egg_alpha_s, PairingGroup('SS512')).decode("utf-8")
        # with open('eggas.yaml','w') as f:
        #     yaml.dump(eggas, f)                
        
        TKgen_result = VTK ** CTUVK
    # print result----------------------------------------------------------------
        # print("publisher: ", egg_alpha_s)
        # print("broker: ", TKgen_result)
        # if egg_alpha_s == TKgen_result:
        #     print("publisher result = broker result")
# -------------------------------------------------------------------------------

        # dec
        # VTK = VTK ** z_0
        # PT1a = dac.decrypt(CT, VTK, trusted_party_decrypt_key['keys'][1])
        # AES_key = objectToBytes(PT1a,PairingGroup('SS512')).decode("utf-8")
        # dec_result = self.AES_decrypt(cipher_text,AES_key)
        # print(dec_result)

# send CT to broker (after policy update)------------------------------------------
        # BytesCT= objectToBytes(CT,PairingGroup('SS512')).decode("utf-8")
        # CTdata = {'CT' : BytesCT}
        # rCT = requests.post('https://'+setting['BrockerIP']+':443/Ciphertext/', data = CTdata, verify=False)
        # json_obj = json.loads(rCT.text)

        # print(bytesToObject(json_obj['result'],PairingGroup('SS512')))
# -------------------------------------------------------------------------------
        return (cipher_AES_key,cipher_text,CT['policy'],secret,old_shares_list)  #return CT['policy']

if __name__ == '__main__':
    encryption = Encryption()
    encryption.encrypt('123')
