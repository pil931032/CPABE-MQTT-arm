import random
import time
from rich.console import Console
from rich.table import Table
import os

class Render:

    def table(self,CPU_Temperature="N/A",CPU_Usage="N/A",RAM_Usage="N/A",Cipher_Key="N/A",Cipher_Text="N/A",Plain_text="N/A",Brocker_IP="N/A",Proxy_IP="N/A",Policy="N/A",Topic="N/A",Time="N/A"):
        os.system('clear')
        table = Table()

        table.add_column("", justify="right", style="cyan", no_wrap=True)
        table.add_column("Publisher -> Broker", justify="left", style="red")

        table.add_row("Device", "Raspberry Pi 3 Model A+")
        table.add_row("CPU Temperature", CPU_Temperature + " °C")
        table.add_row("CPU Usage", CPU_Usage +" %")
        table.add_row("RAM Usage", RAM_Usage +" %")
        table.add_row("Plain text", Plain_text)
        table.add_row("Cipher AES Key", Cipher_Key)
        table.add_row("Cipher Text", Cipher_Text)
        table.add_row("Brocker IP", Brocker_IP)
        table.add_row("Policy", Policy)
        table.add_row("Topic", Topic)
        # table.add_row("Time", Time)
        console = Console()
        console.print(table)

if __name__ == '__main__':
    while True:
        os.system('clear')
        render = Render()
        render.table("50","50","50","AAA")
        time.sleep(2)
    