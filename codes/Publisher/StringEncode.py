from binascii import hexlify, unhexlify

class StringEncode:
    def string_to_integer(self,text:str)->int:
        bytes_string = bytes(text, 'utf-8')
        hex_string = hexlify(bytes_string)
        return int(hex_string, 16)

    def integer_to_string(self,text_integer:int)->str:
        hex_int = "{0:x}".format(text_integer)
        if len(hex_int) % 2 == 1:
            hex_int = "0" + hex_int
        bytes_string = unhexlify(hex_int)
        return bytes_string.decode("utf-8")