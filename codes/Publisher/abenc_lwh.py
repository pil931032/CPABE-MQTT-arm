from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS

class ABENCLWH(DACMACS):
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
        # print("secret in abenc_lwh:",secret)
        shares = self.util.calculateSharesList(secret, policy)  #list
        old_shares = shares #preserved for policy compare
        # print("old shares in abenc:",old_shares)
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])  #dict
        # print(authAttrs)
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
        
        return {'C1': C1, 'C2': C2, 'C3': C3, 'C': C, 'D': D, 'DS': DS, 'policy': policy_str, 'secret': secret, 'old_shares': old_shares}
        

    
    # def generateTK(self, GPP, CT, UASK, g_u):
    #     pass

    # def decrypt(self, CT, TK, z):
    #     pass

    # def ukeygen(self, GPP, authority, attribute, userObj):
    #     pass

if __name__ == '__main__':
    groupObj = PairingGroup('SS512')
    dac = ABENCLWH(groupObj)