import logging
import asyncio
import yaml
import json
from Decryption import Decryption
from Render import Render
from amqtt.client import MQTTClient, ClientException
from amqtt.mqtt.constants import QOS_0,QOS_1, QOS_2
import datetime
import os
from colorama import Fore, Back, Style

logger = logging.getLogger(__name__)

def load_setting():
    with open('setting.yaml', 'r') as f:
        return yaml.safe_load(f)

def load_subscriber_user_password():
    with open('subscriber_user_password.yaml', 'r') as f:
        return yaml.safe_load(f)

async def uptime_coro():
    setting = load_setting()
    user_password = load_subscriber_user_password()
    C = MQTTClient()
    await C.connect('mqtt://'+setting['BrockerIP']+'/')
    await C.subscribe([('message/public', QOS_2),])
    while True:
        try:
            message = await C.deliver_message()
            packet = message.publish_packet
            message_text = str(packet.payload.data,encoding='utf-8')
            receive_time = datetime.datetime.now()
            message_obj = json.loads(message_text)
            # Cipher Text
            Cipher_AES_Key = message_obj['Cipher_AES_Key']
            Cipher_Text = message_obj['Cipher_Text']
            # Decryption
            decryption = Decryption()
            start_decrypt_time = datetime.datetime.now()
            try:
                plain_text,user_attribute,outsourcing_total_time,local_decrypt_total_time = decryption.decryption(Cipher_AES_Key,Cipher_Text)
            except:
                os.system('clear')
                print( Fore.RED + "========= Decrypt fail =========")
                continue
            finish_decrypt_time = datetime.datetime.now()
            # Time-consuming calculation
            start_time = datetime.datetime.fromtimestamp(message_obj['UTC-Time'])
            finish_time = datetime.datetime.now()
            total_time_string = str((finish_time - start_time).total_seconds())
            total_decrypt_time = str((finish_decrypt_time - start_decrypt_time).total_seconds())
            transmission_time = str((receive_time - start_time).total_seconds())
            outsourcing_total_time = str(outsourcing_total_time.total_seconds())
            local_decrypt_total_time =  str(local_decrypt_total_time.total_seconds())
            Render
            result = json.loads(plain_text)
            render = Render()
            render.table(
                CPU_Temperature=str(result['CPU_Temperature']),
                CPU_Usage=str(result['CPU_Usage']),
                RAM_Usage=str(result['RAM_Usage']),
                Decrypted_text = json.dumps(result),
                Cipher_Key = Cipher_AES_Key,
                Cipher_Text = Cipher_Text,
                Brocker_IP = setting['BrockerIP'],
                Proxy_IP = setting['ProxyIP'],
                User = user_password['user'],
                User_ATTRIBUTE = user_attribute,
                Decrypt_Time = total_decrypt_time,
                Transmission_Time = transmission_time,
                Outsourcing_Time = outsourcing_total_time,
                Local_Decrypt_time = local_decrypt_total_time,
                Total_Time = total_time_string,
            )
        except KeyboardInterrupt:
            await C.unsubscribe(['message/public'])
            await C.disconnect()
            break


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(uptime_coro())