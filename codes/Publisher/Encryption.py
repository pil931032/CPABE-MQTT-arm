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

    def encrypt(self,message:str):
        dac = ABENCLWH(PairingGroup('SS512'))
        string_encode = StringEncode()
        message_int:int = string_encode.string_to_integer(message)
        # Load server ip
        setting = self.load_setting()
        policy_str = setting['Policy']

        GPP,authorities = self.get_global_parameter()
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

        # EncryptionInfo = dict()
        # EncryptionInfo['secret'] = secret
        # EncryptionInfo['old_shares_list'] = old_shares_list
        # data = json.dump(EncryptionInfo)
        # with open('EnInfo.json', 'w') as EI:
        #     json.dump(data, EI)
        

        pc = PolicyCompare(PairingGroup('SS512'))
        I1,I2,I3,new_shares_list = pc.compare(secret,old_shares_list)
        # print("I1 list:",I1)
        # print("I2 list:",I2)
        # print("I3 list:",I3)
        # print("old_shares_list:",old_shares_list)
        # print("new_shares_list:",new_shares_list)

        # print(new_shares_list[I1[0][0]-1][1],old_shares_list[I1[0][1]-1][1])
        # print(new_shares_list[I1[1][0]-1][1],old_shares_list[I1[1][1]-1][1])
        # print(new_shares_list[I1[2][0]-1][1],old_shares_list[I1[2][1]-1][1])
        # print(" ")
        
        type1_UK, type2_UK_1, type2_UK_2, type3_UK_1, type3_UK_2, type3_UK_3 = [], [], [], [], [], []
        for i in I1:
            a = new_shares_list[i[0]-1][1]
            b = old_shares_list[i[1]-1][1]
            type1_UK.append(a - b) 
        # print("type1_UK ", type1_UK)
        
        for i in I2:
            a = new_shares_list[i[0]-1][1]
            b = old_shares_list[i[1]-1][1]
            type2_UK_1.append(a - b) 
            type2_UK_2.append(pc.group.random())
        # print("type2_UK_1 ", type2_UK_1)
        # print("type2_UK_2 ", type2_UK_2)


        new_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in new_shares_list])
        old_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in old_shares_list])
        attr_key = list(new_shares_dict)
        # print(attr_key)
        _, APK, authAttrs = authorities
        for i in I3:
            lambda_prime = new_shares_list[i[0]-1][1]
            
            attrPK = authAttrs[attr_key[i[0]-1]]
            r_i_prime = pc.group.random()
            type3_UK_1.append((GPP['g_a'] ** lambda_prime) * ~(attrPK['PK'] ** r_i_prime))
            type3_UK_2.append(APK['g_beta_inv'] ** r_i_prime)
            type3_UK_3.append(~(APK['g_beta_gamma'] ** r_i_prime))
        # print("type3_UK_1", type3_UK_1)
        # print("type3_UK_2", type3_UK_2)
        # print("type3_UK_3", type3_UK_3)
        # print("\n")
        # print(CT)
        list_new = list(new_shares_dict)
        list_old = list(old_shares_dict)
        
        for i, j in zip(I1, type1_UK):
            # print(list_old[i[1]-1],"before update:")
            # print(CT['C'][list_old[i[1]-1]])  #print parameter 'C' before updation
            CT['C'][list_old[i[1]-1]] = CT['C'][list_old[i[1]-1]] * (GPP['g_a'] ** j) #update parameter 'C'
            # print(list_old[i[1]-1],"after update:")
            # print(CT['C'][list_old[i[1]-1]],"\n")  #print parameter 'C' after updation
        # print(CT)

        for i, j1, j2, j3 in zip(I3, type3_UK_1, type3_UK_2, type3_UK_3):
            # print(list_new[i[0]-1])
            CT['C'][list_new[i[0]-1]] = j1
            CT['D'][list_new[i[0]-1]] = j2
            CT['DS'][list_new[i[0]-1]] = j3
        # print(CT)


        CT['policy'] = setting['NewPolicy']

        cipher_AES_key = objectToBytes(CT, PairingGroup('SS512')).decode("utf-8")
        cipher_text = self.AES_encrypt(message,AES_Key_base64_utf8)
        # print("Origin AES Key")
        # print(AES_Key_base64_utf8)
        # Test Decode
        test_d = cipher_AES_key.encode('utf-8')
        bytesToObject(test_d,PairingGroup('SS512'))
        # print('Success!',cipher_AES_key)
        

# trapdoor------------------------------------------------
        search_kw_list = setting['search_kw']
        keyword_list = setting['keyword']
        # print(search_kw_list)
        u = dac.group.random()        
        rho2 = dac.group.random()
        rho2_inv = rho2 ** (-1)
        search_kw_val_in_z_p = []
        for keyword_name in search_kw_list:
            # print(keyword_list[keyword_name])
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
                # T5.append(rho2_inv * (search_kw_val_in_z_p[0] ** (l1) + search_kw_val_in_z_p[1] ** (l1) + search_kw_val_in_z_p[2] ** (l1)))
        # print(T5)
# search test------------------------------------------------
        # print(CT['C2'], T1)
        left = pair(CT['C2'], T1)
        print("left: ", left)
        
        # print("I_hat: ", type(CT['I_hat']))
        # print("T5: ", type(T5))
        right_result = rho2 - rho2
        for i, j in zip(CT['I_hat'], T5):
            right_result = right_result + i * j  
        # print(right_result)
        right = CT['E'] ** (T3 * right_result)
        print("right: ", right)
        
        if left == right:
            print("left == right")
#------------------------------------------------------------
        return (cipher_AES_key,cipher_text,CT['policy'])  #return CT['policy']

if __name__ == '__main__':
    encryption = Encryption()
    encryption.encrypt('123')
