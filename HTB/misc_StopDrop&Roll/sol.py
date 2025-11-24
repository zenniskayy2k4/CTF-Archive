from pwn import *

HOST = "83.136.253.59"
PORT = 47589

rules = {
    "GORGE": "STOP",
    "PHREAK": "DROP",
    "FIRE": "ROLL"
}

conn = remote(HOST, PORT)

conn.recvuntil(b"Are you ready? (y/n)")
conn.sendline(b"y")

conn.recvuntil()

try:
    while True:
        line = conn.recvline().strip().decode()
        
        if "HTB{" in line:
            print("\nFlag found:", line)
            break
        
        print(f"Server says: {line}")
        
        scenarios = line.split(", ")
        
        responses = []
        for scenario in scenarios:
            action = rules[scenario]
            responses.append(action)

        final_response = "-".join(responses)
        
        conn.recvuntil(b"What do you do? ")
        
        print(f"Sending response: {final_response}")
        conn.sendline(final_response.encode())
        
except EOFError:
    print("Connection closed by server.")
    
finally:
    conn.close()
    print("Connection closed.")