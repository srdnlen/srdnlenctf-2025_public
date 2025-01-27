from hashlib import md5
import string 
import random


charset = string.printable
flag = "srdnlen{Mr_Evrart_is_helping_me_find_my_flag_af04993a13b8eecd}"

#Create hashes for all individual characters, except the correct one if we're generating for the flag.
def gen_substr_set(hash_set, substr, c=None):
    for x in charset:
        if c is not None and c == x: continue
        hash_set.add(md5(str(substr+x).encode("ascii")).digest())
        print(f"Added md5 of {substr+x}")
    return hash_set


# Generate the first batch of hashes for wrong paths. The only correct path for the full-length flag is the right letters.
def create_base_set(flag):
    res = set()
    for i in range(len(flag)):
        substr = flag[:i]
        c = flag[i]
        res = gen_substr_set(res,substr,c) #Add hashes for all chars except the correct one.
    return res

# Add dead ends: wrong, but unflagged, individual characters which lead to all-wrong hash paths
def add_rec_deadend_tree(hash_set, substr, depth, branches=3):
    idx = len(substr)
    if depth == 0:
        return gen_substr_set(hash_set, substr) #Add hashes for all following chars
    else:
        potential_chars = set(charset)
        potential_chars.remove(flag[idx]) # This is technically incorrect in intermediate subtrees (depth > 2), but it's a minor loss with no consequence.
        chars = random.sample(sorted(potential_chars), branches)
        for c in chars:
            new_substr = substr + c
            hash_set.add(md5(new_substr.encode("ascii")).digest()) # Hack: add to set to avoid keyErrors on intermediate subtrees.        
            hash_set.remove(md5(new_substr.encode("ascii")).digest())
            hash_set = gen_substr_set(hash_set,new_substr) # Add all level-1 dead ends, THEN add following branches
            hash_set = add_rec_deadend_tree(hash_set,new_substr,depth-1,branches)
        return hash_set

hs = create_base_set(flag)
print(len(hs))

for depth in range(1,4):
    for i in range(len(flag)-depth):
        hs = add_rec_deadend_tree(hs,flag[:i],depth)
print(len(hs))

def write_bank_to_file(hash_set, filename):
    with open(filename, "wb") as f:
        for h in hash_set:
            f.write(h)

write_bank_to_file(hs, "hardcore.bnk")
