from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import yaml

class PolicyCompare:
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)  #Create Secret Sharing Scheme
        self.group = groupObj    #:Prime order group

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)
        
    def compare(self,s,old_shares_list): 
        setting = self.load_setting()
        # old_policy_str = setting['Policy']
        new_policy_str = setting['NewPolicy']

    #string->policy object
        # old_policy = self.util.createPolicy(old_policy_str)
        new_policy = self.util.createPolicy(new_policy_str)

        # secret = self.group.random()
        secret = s

    #calculate shares
        # old_shares_list = self.util.calculateSharesList(secret, old_policy)

        # print("old shares in PolicyCompare:",old_shares_list)
        new_shares_list = self.util.calculateSharesList(secret, new_policy)
        # print("new shares in PolicyCompare:",old_shares_list)
        I_M_index=0
        I_M=[]
        old_row_i=[]
        old_policyM=[]
        for x in old_shares_list:
            I_M_index+=1
            I_M.append(I_M_index)
            old_row_i.append(x[0])
            old_policyM.append(x[0])

        new_row_i=[]
        I_M_prime_index=0
        I_M_prime=[]
        for x in new_shares_list:
            I_M_prime_index+=1
            I_M_prime.append(I_M_prime_index)
            new_row_i.append(x[0])
        I1=[]
        I2=[]
        I3=[]
        for indexJ , j in enumerate(new_row_i,start=1):
            if j in old_policyM:
                for indexI, i in enumerate(old_policyM,start=1):
                    
                    if (indexI in I_M) and (indexJ in I_M_prime) and (old_row_i[indexI-1]==new_row_i[indexJ-1]):
                        I1.append((indexJ,indexI))
                        # print(old_row_i[indexI-1],"=",new_row_i[indexJ-1])
                        # print("before rm I:",indexI,I_M)
                        I_M.remove(indexI)
                        # print("after rm I:",indexI,I_M)
                        # print("before rm J:",indexJ,I_M_prime)
                        I_M_prime.remove(indexJ)
                        # print("after rm J:",indexJ,I_M_prime)
                        flag = False
                    elif (indexJ in I_M_prime) and (indexI not in I_M) and (old_row_i[indexI-1]==new_row_i[indexJ-1]):
                        I2.append((indexJ,indexI))

                        # print(old_row_i[indexI-1],"=",new_row_i[indexJ-1])
                        # I_M_prime.remove(indexJ)
                        # continue
                        # print(I_M_prime)
            else:
                I3.append((indexJ,0))            

        # print("I_M:",I_M)
        # print("I1 list:",I1)
        # print("I2 list:",I2)
        # print("I3 list:",I3)

# Policy: ((WORKER and OFFICER) and (DEVELOPER or MAINTAINER))
# NewPolicy: ((OFFICER or WORKER) and MAINTAINER)

# Policy: ((A or B) and (B and (C and (B or (D and C))))))
# NewPolicy: ((C or B) and (B and (C and B)) and F)

# Policy: (A and (B and (C and D)))
# NewPolicy: ((A or B) and (B and ((C or E) and (B or (D or F))))))

# Policy: ((WORKER and OFFICER) and MAINTAINER)
# NewPolicy: ((OFFICER or WORKER) and (DEVELOPER or MAINTAINER))

        # old_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in old_shares_list])
        # new_shares_dict = dict([(x[0].getAttributeAndIndex(), x[1]) for x in new_shares_list])
        # print(old_shares_dict)
        # print(new_shares_dict)

        return(I1,I2,I3,new_shares_list)
    

if __name__ == '__main__':
    groupObj = PairingGroup('SS512')
    pc = PolicyCompare(groupObj)

    #new random secret
    secret=pc.group.random()

    #produce a new old_shares_list
    setting = pc.load_setting()
    old_policy_str = setting['Policy']
    old_policy = pc.util.createPolicy(old_policy_str)
    old_shares_list = pc.util.calculateSharesList(secret, old_policy)

    I1,I2,I3,new_shares_list=pc.compare(secret,old_shares_list)
    print("I1 list:",I1)
    print("I2 list:",I2)
    print("I3 list:",I3)