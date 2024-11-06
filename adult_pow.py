import socket
import re
import sys
import subprocess
import os
import time

# Configuration
HOST = '85.120.206.56'
PORT = 31338
TIMEOUT = 300  # 5 minutes

# Hashcat configuration
HASH_MODE = '1400'  # SHA-256
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn0123456789"
MASK = '?1?1?1?1?1'
HASHCAT_PATH = 'C:\\Users\\ThinkBook\\Downloads\\hashcat-6.2.6\\hashcat-6.2.6\\hashcat.exe'

def run_hashcat(target_hash):
    """
    Runs Hashcat to find the plaintext string corresponding to the target_hash.
    
    Parameters:
        target_hash (str): The SHA-256 hash to crack.
        
    Returns:
        str or None: The cracked string if found, else None.
    """
    # Create temporary files
    hash_file = 'hash.txt'
    cracked_file = 'cracked.txt'
    
    with open(hash_file, 'w') as f:
        f.write(target_hash + '\n')
    
    # Remove existing cracked file if exists
    if os.path.exists(cracked_file):
        os.remove(cracked_file)
    
    # Construct Hashcat command
    cmd = [
        HASHCAT_PATH,
        '-m', HASH_MODE,
        '-a', '3',
        '-1', CHARSET,
        hash_file,
        MASK,
        '--quiet',
        '--outfile', cracked_file,
        '--force'  # To bypass warnings; use with caution
    ]
    
    try:
        # Run Hashcat
        print(f"Executing Hashcat command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Hashcat failed: {e}")
        return None
    
    # Check if cracked file has output
    if os.path.exists(cracked_file):
        with open(cracked_file, 'r') as f:
            cracked_line = f.read().strip()
            if cracked_line:
                # Split the line by ':' to separate hash and plaintext
                parts = cracked_line.split(':')
                if len(parts) == 2:
                    cracked = parts[1]  # Extract plaintext
                    return cracked
                else:
                    print("Unexpected format in cracked.txt.")
                    return None
    
    return None

def cleanup():
    """
    Removes temporary files created during the cracking process.
    """
    for file in ['hash.txt', 'cracked.txt']:
        if os.path.exists(file):
            os.remove(file)

def main():
    try:
        # Establish socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            print(f"Connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("Connected successfully.\n")

            # Buffer to accumulate received data
            buffer = b''

            for challenge_num in range(1, 6):
                print(f"--- Challenge {challenge_num} ---")

                # Receive data until "Mine xxxx:" prompt
                while b"Mine xxxx:" not in buffer:
                    data = s.recv(4096)
                    if not data:
                        print("Connection closed by the server.")
                        cleanup()
                        sys.exit(1)
                    buffer += data

                # Decode buffer to string
                buffer_str = buffer.decode()

                # Use regex to extract the hash
                # Example challenge line: sha256(xxxx) == <hash>
                pattern = r'sha256\(xxxx\) == ([a-fA-F0-9]{64})'
                match = re.search(pattern, buffer_str)
                if not match:
                    print("Failed to parse the challenge.")
                    cleanup()
                    sys.exit(1)

                target_hash = match.group(1)
                print(f"Received hash: {target_hash}")

                # Run Hashcat to find the string
                print("Running Hashcat to crack the hash...")
                start_time = time.time()
                s_found = run_hashcat(target_hash)
                end_time = time.time()

                if s_found:
                    print(f"Cracked string: {s_found} (Time taken: {end_time - start_time:.2f} seconds)")
                    # Send the cracked string back to the server
                    s.sendall((s_found + '\n').encode())
                else:
                    print("Failed to crack the hash.")
                    cleanup()
                    sys.exit(1)

                # Clear the buffer up to "Mine xxxx:" prompt
                buffer = buffer.split(b"Mine xxxx:")[1]

            # After solving all challenges, receive the proof token
            print("All challenges solved. Receiving proof token...\n")
            proof = b''
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    proof += data
                except socket.timeout:
                    break

            proof_str = proof.decode()
            print("Proof Token:")
            print(proof_str)

    except socket.timeout:
        print("Socket timed out.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
