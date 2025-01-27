import hashlib
import string

MD5_LEN = 16

#Create hashset
def import_bank(path="./hardcore.bnk"):
    hashes = open(path, 'rb').read()
    res = set()
    for i in range(len(hashes)//MD5_LEN):
        res.add(hashes[i*MD5_LEN:(i+1)*MD5_LEN])
    return res

bank = import_bank()

FLAG_LEN = 62

def dfs(substr=""):
    subh = hashlib.md5(substr.encode('ascii')).digest()
    #First, check if current substring is in blacklist.
    if subh not in bank:
        #If substring is full flag, print and return
        if len(substr) == FLAG_LEN:
            print(substr)
            exit()
        for c in string.printable:
            dfs(substr+c)
    return    

dfs()