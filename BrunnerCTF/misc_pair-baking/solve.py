from pwn import *
import base64

# Set these when connecting to remote
HOST = ''
PORT = 0
REMOTE = False

BINARY_PATH = './solver/solver'

# Optional: context for debugging
context.log_level = 'info'

# Load and base64-encode your binary
with open(BINARY_PATH, 'rb') as f:
    binary_data = f.read()

b64_data = base64.b64encode(binary_data)

# Connect to the challenge server
if REMOTE:
    io = remote(HOST, PORT, ssl=True)
else:
    io = remote('localhost', 5000)

# Wait for the prompt
io.recvuntil(b'Send base64 encoded binary (end with newline):')

# Send base64-encoded binary + newline
io.sendline(b64_data)

# Get the result from the "second" execution (without flag access)
response = io.recvall(timeout=100).decode(errors='ignore')

print("\n===== Server Response =====")
print(response)
print("===== End =====")

io.close()
