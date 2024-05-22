from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS
import yaml


class ABENCLWH(DACMACS):
    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)  #Create Secret Sharing Scheme
        self.group = groupObj    #:Prime order group
    # def setup(self):
    #     '''Global Setup (executed by CA)'''
    #     #:In global setup, a bilinear group G of prime order p is chosen
    #     #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G
    
    #     #:group contains 
    #     #:the prime order p is contained somewhere within the group object
    #     g = self.group.random(G1)
    #     #: The oracle that maps global identities GID onto elements of G
    #     #:H = lambda str: g** group.hash(str)
    #     H = lambda x: self.group.hash(x, G1)
    #     a = self.group.random()
    #     g_a = g ** a
    #     GPP = {'g': g, 'g_a': g_a, 'H': H}
    #     GMK = {'a': a}
        
    #     return (GPP, GMK)

    # def registerUser(self, GPP):
    #     pass

    # def setupAuthority(self, GPP, authorityid, attributes, authorities):
    #     pass

    # def keygen(self, GPP, authority, attribute, userObj, USK = None):
    #     pass

    def encrypt(self, GPP, policy_str, k, authority):
        '''Generate the cipher-text from the content(-key) and a policy (executed by the content owner)'''
        #GPP are global parameters
        #k is the content key (group element based on AES key)
        #policy_str is the policy string
        #authority is the authority tuple
        
        _, APK, authAttrs = authority
        policy = self.util.createPolicy(policy_str)
        # print(policy)
        # print(type(policy))
        secret = self.group.random()
        rho1 = self.group.random()
        rho1_inv = rho1 ** (-1)
        # print("secret in abenc_lwh:",secret)
        shares = self.util.calculateSharesList(secret, policy)  #list
        old_shares = shares #preserved for policy compare
        # print("old shares in abenc:",old_shares)
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])  #dict
        # print(authAttrs)


# hash keyword -------------------------
        setting = self.load_setting()
        keyword_list = setting['keyword']
        # keyword_val_in_z_p = {}
        keyword_val_in_z_p_a = []
        I_hat = []
        # print(keyword_list['kw0'])
        for keyword_name in keyword_list:
            # print(keyword_list[keyword_name])
            keyword_val = self.group.hash(keyword_list[keyword_name], type=ZR)
            keyword_val_in_z_p_a.append(keyword_val)
            # keyword_val_in_z_p[keyword_name] = keyword_val


        # print(keyword_val_in_z_p)
        # print(keyword_val_in_z_p_a)
        a = keyword_val_in_z_p_a[0]
        b = keyword_val_in_z_p_a[1]
        c = keyword_val_in_z_p_a[2]
        d = keyword_val_in_z_p_a[3]

        # Coefficient of x^4
        coef_x4 = a / a 
        # Coefficient of x^3
        coef_x3 = -(a + b + c + d)
        # Coefficient of x^2
        coef_x2 = (a*b + a*c + a*d + b*c + b*d + c*d)
        # Coefficient of x
        coef_x1 = -(a*b*c + a*b*d + a*c*d + b*c*d)
        # Constant term
        constant = a * b * c * d + 1



# test equation---------------------------------------
        # specific_x = self.group.hash("v_kw1", type=ZR)
        # result_test = (specific_x ** 4) + coef_x3 * (specific_x ** 3) + coef_x2 * (specific_x ** 2) + coef_x1 * (specific_x ** 1) + constant
        # print("result = ", result_test)
# E and I_hat---------------------------------------
        E = pair(GPP['g'], GPP['g']) ** (secret * rho1)
        # print("E= ", E)
        I_hat.append(rho1_inv * constant)
        I_hat.append(rho1_inv * coef_x1)
        I_hat.append(rho1_inv * coef_x2)
        I_hat.append(rho1_inv * coef_x3)
        I_hat.append(rho1_inv * coef_x4)
        # print(I_hat)        
# ---------------------------------------------------
        C1 = k * (APK['e_alpha'] ** secret)
        C2 = GPP['g'] ** secret
        C3 = APK['g_beta_inv'] ** secret
        C = {}
        D = {}
        DS = {}
        # if 'WORKER_0' in shares.keys():

            # shares['WORKER'] = shares['WORKER_0']

        for attr, s_share in shares.items():
            k_attr = self.util.strip_index(attr)
            r_i = self.group.random()

            # attrPK = authAttrs[attr]

            if attr == 'A_0' or attr == 'A_1':
                attrPK = authAttrs['A']
            else:
                attrPK = authAttrs[attr]
            
            C[attr] = (GPP['g_a'] ** s_share) * ~(attrPK['PK'] ** r_i)
            D[attr] = APK['g_beta_inv'] ** r_i
            DS[attr] = ~(APK['g_beta_gamma'] ** r_i)
        
        E = pair(GPP['g'], GPP['g']) ** (secret * rho1)
        # print("E= ", E) 

        return {'C1': C1, 'C2': C2, 'C3': C3, 'C': C, 'D': D, 'DS': DS, 'policy': policy_str, 'secret': secret, 'old_shares': old_shares,'E': E, 'I_hat': I_hat}
        

    
    # def generateTK(self, GPP, CT, UASK, g_u):
    #     pass

    # def decrypt(self, CT, TK, z):
    #     pass

    # def ukeygen(self, GPP, authority, attribute, userObj):
    #     pass

if __name__ == '__main__':
    groupObj = PairingGroup('SS512')
    dac = ABENCLWH(groupObj)