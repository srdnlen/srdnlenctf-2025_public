from pwn import *
import string

context.log_level = 'error'
# Binary to interact with
binary_path = './egghead'  # Replace with the actual binary path
def find_possible_chars(flag):
    printable_chars = string.digits + string.ascii_lowercase + string.ascii_uppercase +'-' + '_' + '}' # Possible characters to try
    possible = ""
    # while True:
    for i in printable_chars:
        process_instance = process(binary_path)
        
        try:
            # Send the current flag one character at a time
            for j in flag:
                process_instance.recvline()  # Wait for the prompt
                process_instance.sendline(j)  # Send the current character of the flag

            # Test the next character
            process_instance.recvline()  # Wait for the prompt
            process_instance.sendline(i)

            # Receive output from the binary
            output = process_instance.recvrepeat(timeout=0.01).decode()

            if "Hey it looks like you have input the right flag. Why are you still here?" in output:
                print(f"[+] Completed flag: {flag + i}")
                exit()
                possible += i

            if "There has to be some way to talk to this person, you just haven't found it yet." not in output:
                # flag += i
                #print(f"[+] Flag so far: {flag}")
                possible += i
                # break

        except EOFError:
            # Handle unexpected binary termination
            process_instance.close()
            continue

        # Close the process after each attempt
        process_instance.close()
    
    print(f"Possible chars for  {flag}: {possible}")
    return possible


def dfs(current_flag: str) -> str:
    # Goal condition: if we've reached 62 chars, we stop
    if len(current_flag) == 62:
        return current_flag  # Found a valid flag
    
    # Get possible next characters from your function
    possible_next = find_possible_chars(current_flag)
    if not possible_next:
        
        return ""  # No possible path forward, backtrack
    
    # Try each possible character in a DFS manner
    for c in possible_next:
        result = dfs(current_flag + c)
        if result:  # If the recursion found a solution, bubble it up
            print(f"Found potential path {result}")
            return result
    
    return ""  # If none of the branches led to a solution, return empty


def main():
    start_flag = "srdnlen{"
    print(f"Starting DFS from prefix: {start_flag}")
    
    final_flag = dfs(start_flag)
    if final_flag:
        print(f"Flag found: {final_flag}")
    else:
        print("No valid flag could be constructed.")

if __name__ == "__main__":
    main()
