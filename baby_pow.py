import socket
import hashlib
import string
import itertools
import re
import sys

# Configuration
HOST = '85.120.206.56'
PORT = 31337
TIMEOUT = 10  # seconds

# Define the hash functions
hash_funcs = {
    'sha256': hashlib.sha256,
    'md5': hashlib.md5,
    'keccak': hashlib.sha3_256
}

# Character set: ASCII letters and digits
charset = string.ascii_letters + string.digits

def brute_force(prefix_len, suffix, target_hash, hash_func):
    """
    Brute-force to find the prefix of length prefix_len such that:
    hash_func(prefix + suffix) == target_hash
    """
    print(f"Brute-forcing prefix of length {prefix_len}...")
    for candidate in itertools.product(charset, repeat=prefix_len):
        prefix = ''.join(candidate)
        combined = prefix + suffix
        combined_bytes = combined.encode()
        hash_value = hash_func(combined_bytes).hexdigest()
        if hash_value == target_hash:
            print(f"Found prefix: {prefix}")
            return prefix
    print("Prefix not found.")
    return None

def main():
    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"Connection error: {e}")
            sys.exit(1)
        
        # Buffer to accumulate received data
        buffer = b''
        
        for challenge_num in range(1, 16):
            try:
                # Receive data until "Mine xxxx:" prompt
                while b"Mine xxxx:" not in buffer:
                    data = s.recv(4096)
                    if not data:
                        print("Connection closed by the server.")
                        sys.exit(1)
                    buffer += data
                
                # Decode buffer to string
                buffer_str = buffer.decode()
                
                # Use regex to extract the challenge details
                # Example line: sha256(xxxx + abcdefghij) == <hash>
                pattern = r'(\w+)\(xxxx \+ ([A-Za-z0-9]+)\) == ([a-fA-F0-9]+)'
                match = re.search(pattern, buffer_str)
                if not match:
                    print("Failed to parse the challenge.")
                    sys.exit(1)
                
                chosen_hash, suffix, target_hash = match.groups()
                print(f"Challenge {challenge_num}:")
                print(f"Hash Function: {chosen_hash}")
                print(f"Suffix: {suffix}")
                print(f"Target Hash: {target_hash}")
                
                # Get the hash function from the dictionary
                hash_func = hash_funcs.get(chosen_hash)
                if not hash_func:
                    print(f"Unsupported hash function: {chosen_hash}")
                    sys.exit(1)
                
                # Determine prefix length based on known information
                # Since prefix_len is random between 1 and 4, and the length of 'xxxx' is prefix_len
                # We'll infer it based on the length of the printed 'xxxx', which is prefix_len
                # However, since 'xxxx' is a placeholder, we need to get prefix_len from the actual printed string
                # Alternatively, if prefix_len is not directly provided, we need another way to determine it
                # Looking back at the script, it seems prefix_len is printed as part of "Mine xxxx:"
                # But in our regex, we didn't capture prefix_len directly
                # To handle this, we need to adjust our parsing
                # Let's re-examine the printed lines in the script:
                # print(f"{chosen_hash}(xxxx + {s[prefix_len:]}) == {hash_funcs[chosen_hash](s.encode()).hexdigest()}")
                # print("Mine xxxx:")
                # So, we need to capture prefix_len from the script's output
                # Since we don't have it directly, we might need to infer it
                # Alternatively, we can attempt all possible prefix_len (1 to 4)
                
                # Attempt brute-force for prefix_len from 1 to 4
                found = False
                for prefix_len in range(1, 5):
                    prefix = brute_force(prefix_len, suffix, target_hash, hash_func)
                    if prefix:
                        # Send the found prefix
                        s.sendall((prefix + '\n').encode())
                        found = True
                        break
                if not found:
                    print("Failed to find a valid prefix.")
                    sys.exit(1)
                
                # Clear the buffer up to "Mine xxxx:" prompt
                buffer = buffer.split(b"Mine xxxx:")[1]
                
            except socket.timeout:
                print("Socket timed out.")
                sys.exit(1)
            except Exception as e:
                print(f"An error occurred: {e}")
                sys.exit(1)
        
        # After 15 challenges, receive the proof token
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                print(data.decode(), end='')
        except socket.timeout:
            pass

if __name__ == "__main__":
    main()
