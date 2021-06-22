###########################################################################################################


red =  "\033[1;31m"
gre = "\033[1;32m"
ye = "\033[1;33m"
cy = "\033[1;36m"
gray = "\033[m"
wh = "\033[1;37m"


###########################################################################################################


from argparse import ArgumentParser
from string import ascii_uppercase
from os import _exit
import random


###########################################################################################################


def banner():
    print("")
    print("{}\t\t\t  /$$$$$$  /$$   /$$ /$$$$$$$ ".format(ye, ye))
    print("{}\t\t\t /$$__  $$| $$  | $$| $$__  $$".format(ye, ye))
    print("{}\t\t\t| $$  \\__/| $$  | $$| $$  \\ $$".format(ye, ye))
    print("{}\t\t\t|  $$$$$$ | $$  | $$| $$$$$$$ ".format(ye, ye))
    print("{}\t\t\t \\____  $$| $$  | $$| $$__  $$".format(ye, ye))
    print("{}\t\t\t /$$  \\ $$| $$  | $$| $$  \\ $$".format(ye, ye))
    print("{}\t\t\t|  $$$$$$/|  $$$$$$/| $$$$$$$/".format(ye, ye))
    print("{}\t\t\t \\______/  \\______/ |_______/ ".format(ye, ye))                  
    print("")
    print("{} \t\t###############################################".format(red))
    print("{} \t\t\tSusbstitution Cipher Algorithm".format(wh))
    print("{} \t\t\t\tAuthor: Tony Nasr".format(wh))
    print("{} \t\t###############################################".format(red))
    print(gray + "\n")


###########################################################################################################


class ENC:

    def __init__(self, debug=True):
        self.plain = None
        self.key = None
        self.cipher = ""
        self.debug = debug


    def print_error(self, msg):
        print(" {0}[{1}!{0}] {1}ERROR{2}: {0}{3}\n".format(wh, red, ye, msg.title()))
        _exit(0)


    def print_msg(self, title, msg):
        print(" {0}[{1}+{0}]{2} ================================= {1}{3} {0}[{2}{4}{0}]{2}".format(wh, gre, ye, title.upper(), len(msg)))
        print(" {0}[{1}+{0}] {2}{3}\n".format(wh, gre, cy, msg))


    def get_plain(self, filename):
        try:
            with open(filename, "r") as f:
                content = f.read()
        except:
            self.print_error("the provided plaintext file does not exist")
        if not content:
            self.print_error("the provided plaintext file does not contain any data")
        data = content.upper().replace(" ", "")
        self.plain = "".join([x for x in data if x in ascii_uppercase])
        if self.debug:
            self.print_msg("Modified plain-text", self.plain)
        return self.plain


    def get_key(self, key):
        key = key.upper()
        if not key.isalpha():
            self.print_error("the provided encryption key is not purely alphabetic")
        elif len(key) != 26:
            self.print_error("the provided encryption key length must be 26")
        for c in key:
            count = key.count(c)
            if count > 1:
                self.print_error("every character in the encryption key should be different than others")
        self.key = key
        if self.debug:
            self.print_msg("encryption key", self.key)      
        return self.key

    
    def get_cipher(self):
        correspondance = {x:y for x,y in zip(ascii_uppercase, self.key)}
        for c in self.plain.strip():
            self.cipher += correspondance[c]
        if self.debug:
            self.print_msg("cipher-text", self.cipher)
        return self.cipher


###########################################################################################################                   


class DEC:

    def __init__(self, debug=True):
        self.plain = ""
        self.key = None
        self.cipher = None
        self.debug = debug


    def print_error(self, msg):
        print(" {0}[{1}!{0}] {1}ERROR{2}: {0}{3}\n".format(wh, red, ye, msg.title()))
        _exit(0)


    def print_msg(self, title, msg):
        print(" {0}[{1}+{0}]{2} ================================= {1}{3} {0}[{2}{4}{0}]{2}".format(wh, gre, ye, title.upper(), len(msg)))
        print(" {0}[{1}+{0}] {2}{3}\n".format(wh, gre, cy, msg))


    def get_cipher(self, filename):
        try:
            with open(filename, "r") as f:
                content = f.read()
        except:
            self.print_error("the provided ciphertext file does not exist")
        if not content:
            self.print_error("the provided ciphertext file does not contain any data")
        self.cipher = content.upper().replace(" ", "")
        if self.debug:
            self.print_msg("cipher-text", self.cipher)
        return self.cipher


    def get_key(self, key):
        key = key.upper()
        if not key.isalpha():
            self.print_error("the provided encryption key is not purely alphabetic")
        elif len(key) != 26:
            self.print_error("the provided encryption key length must be 26")
        for c in key:
            count = key.count(c)
            if count > 1:
                self.print_error("every character in the encryption key should be different than others")
        self.key = key
        if self.debug:
            self.print_msg("decryption key", self.key)      
        return self.key

    
    def get_plain(self):
        correspondance = {x:y for x,y in zip(self.key, ascii_uppercase)}
        for c in self.cipher.strip():
            self.plain += correspondance[c]
        if self.debug:
            self.print_msg("plain-text", self.plain)
        return self.plain


###########################################################################################################


def main():
    global ARG
    
    banner()
    array = [x for x in ascii_uppercase]
    random.shuffle(array)
    default_key = "".join(array)

    f = ArgumentParser()
    f.add_argument("-f", "--file", help="Input file containing plaintext / ciphertext", default="plain.txt")
    f.add_argument("-k", "--key", help="Encryption / Decryption key to be used in the algorithm", default=default_key)
    f.add_argument("-e", "--encrypt", help="Encrypt input data", action='store_true')
    f.add_argument("-d", "--decrypt", help="Decrypt input data", action='store_true')
    f.add_argument("-ndbg", "--no-debug", help="Disable debugging", action='store_true')    
    arg = f.parse_args()

    debug = True
    if arg.no_debug:
        debug = False
        
    if arg.encrypt:
        module = ENC(debug)
        module.get_plain(arg.file)
        module.get_key(arg.key)
        module.get_cipher()
    elif arg.decrypt:
        module = DEC(debug)
        module.get_cipher(arg.file)
        module.get_key(arg.key)
        module.get_plain()
    else:
        ENC(debug).print_error("must specify a task (encrypt / decrypt)")
                       

###########################################################################################################


if __name__ == '__main__':
    main()


###########################################################################################################


