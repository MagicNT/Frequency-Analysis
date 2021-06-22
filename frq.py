###########################################################################################################


red =  "\033[1;31m"
gre = "\033[1;32m"
ye = "\033[1;33m"
cy = "\033[1;36m"
gray = "\033[m"
wh = "\033[1;37m"


###########################################################################################################


from pycipher import SimpleSubstitution as SimpleSub
from argparse import ArgumentParser
from string import ascii_uppercase
from math import log10
from os import _exit
import random
import re


###########################################################################################################


def banner():
    print("")
    print("{}\t\t\t /$$$$$$$$ /$$$$$$$   /$$$$$$ ".format(ye, ye))
    print("{}\t\t\t| $$_____/| $$__  $$ /$$__  $$".format(ye, ye))
    print("{}\t\t\t| $$      | $$  \\ $$| $$  \\ $$".format(ye, ye))
    print("{}\t\t\t| $$$$$   | $$$$$$$/| $$  | $$".format(ye, ye))
    print("{}\t\t\t| $$__/   | $$__  $$| $$  | $$".format(ye, ye))
    print("{}\t\t\t| $$      | $$  \\ $$| $$/$$ $$".format(ye, ye))
    print("{}\t\t\t| $$      | $$  | $$|  $$$$$$/".format(ye, ye))
    print("{}\t\t\t|__/      |__/  |__/ \\____ $$$".format(ye, ye))
    print("{}\t\t\t                          \\__\/".format(ye, ye))
    print("")
    print("{} \t\t###############################################".format(red))
    print("{} \t\t\tFrequency Crypto-Analysis Algorithm".format(wh))
    print("{} \t\t\t\tAuthor: Tony Nasr".format(wh))
    print("{} \t\t###############################################".format(red))
    print(gray + "\n")


###########################################################################################################


# gets score of text using n-gram probability
class ngram_score(object):

    def __init__(self,ngramfile,sep=' '):
        # read file which has ngrams and counts
        self.ngrams = {}
        for line in open(ngramfile, "r"):
            key,count = line.split(sep) 
            self.ngrams[key] = int(count)
        self.L = len(key)
        self.N = 0
        for x in self.ngrams.items():
            self.N += x[1]
        # calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key])/self.N)
        self.floor = log10(0.01/self.N)


    def score(self,text):
        # compute the score of text
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text)-self.L+1):
            if text[i:i+self.L] in self.ngrams: score += ngrams(text[i:i+self.L])
            else: score += self.floor          
        return score


###########################################################################################################


class FREQUENCY_ANALYSIS:

    def __init__(self):
        self.plain = None
        self.key = None
        self.cipher = None


    def print_error(self, msg):
        print(" {0}[{1}!{0}] {1}ERROR{2}: {0}{3}".format(wh, red, ye, msg.title()))
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
        self.print_msg("cipher-text", self.cipher)
        return True


    def get_key_and_plain(self):
        
        # load quadgram statistics
        fitness = ngram_score('data/quadgrams.txt')
        maxkey = list(ascii_uppercase)
        maxscore = -99e9
        parentscore, parentkey = maxscore, maxkey[:]

        i = 0
        while 1:
            i += 1
            random.shuffle(parentkey)
            deciphered = SimpleSub(parentkey).decipher(self.cipher)
            parentscore = fitness.score(deciphered)
            count = 0
            
            while count < 1000:
                a = random.randint(0,25)
                b = random.randint(0,25)
                child = parentkey[:]
                
                # swap 2 characters in the child
                child[a],child[b] = child[b],child[a]
                deciphered = SimpleSub(child).decipher(self.cipher)
                score = fitness.score(deciphered)
                
                # if the child was better then replace tparent
                if score > parentscore:
                    parentscore = score
                    parentkey = child[:]
                    count = 0
                count += 1
            
            # print score, iteration, possible key and posisble plaintext
            if parentscore > maxscore:
                maxscore, maxkey = parentscore, parentkey[:]
                print(red + "#" * 60 + gray)
                print("\n {0}[{1}~{0}] Score {0}[{1}{2}{0}] {1}| {0}Iteration {0}[{1}{3}{0}]".format(wh, red, maxscore, i))
                ss = SimpleSub(maxkey)
                self.print_msg("cracked key", ''.join(maxkey))
                self.print_msg("cracked plain-text", ss.decipher(self.cipher))


###########################################################################################################


def main():
    global ARG
    
    banner()
    array = [x for x in ascii_uppercase]
    random.shuffle(array)
    default_key = "".join(array)

    f = ArgumentParser()
    f.add_argument("-f", "--file", help="Input file containing ciphertext to be decrypted", default="cipher.txt")
    arg = f.parse_args()


    module = FREQUENCY_ANALYSIS()
    module.get_cipher(arg.file)
    module.get_key_and_plain()


###########################################################################################################


if __name__ == '__main__':
    main()


###########################################################################################################


