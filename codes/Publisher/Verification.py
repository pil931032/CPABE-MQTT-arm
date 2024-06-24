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

class Verification:
    def __init__(self):
        warnings.filterwarnings("ignore")   

    def load_setting(self):
        with open('setting.yaml', 'r') as f:
            return yaml.safe_load(f)

    def requestVTK(self):
        setting = self.load_setting()

        r = requests.post('https://'+setting['BrockerIP']+':443/requestVTK/', verify=False)
        json_obj = json.loads(r.text) 
        VTK = bytesToObject(json_obj['result'],PairingGroup('SS512'))
        # print(VTK)
        with open("CTUVK.yaml") as stream:
            try:
                ctuvk = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        CTUVK = bytesToObject(ctuvk,PairingGroup('SS512'))
        # print(type(VTK))
        TKgen_result = VTK ** CTUVK
        # print(TKgen_result)


        with open("eggas.yaml") as stream:
            try:
                eggas = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        egg_alpha_s = bytesToObject(eggas,PairingGroup('SS512'))

        print("publisher: ", egg_alpha_s)
        print("broker: ", TKgen_result)
        if egg_alpha_s == TKgen_result:
            print("publisher result = broker result")

if __name__ == '__main__':
    v = Verification()
    v.requestVTK()