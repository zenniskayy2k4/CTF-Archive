#!/usr/bin/env python3

import socketserver
import base64
import subprocess
import os
import time

PORT = 5000
MAX_B64_SIZE = 5 * 1024 * 1024  # 5MB max upload size
TIMEOUT = 45  # Process timeout
RUNTIME = TIMEOUT + 10 # To avoid timing based solutions

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"Send base64 encoded binary (end with newline):\n")
            b64_data = b''
            while not b64_data.endswith(b'\n'):
                chunk = self.request.recv(4096)
                if not chunk:
                    print("Did not get chunk")
                    self.request.sendall(b"Connection interrupted\n")
                    return
                b64_data += chunk
                if len(b64_data) > MAX_B64_SIZE:
                    self.request.sendall(b"Too big!\n")
                    return
            b64_data = b64_data.strip()
            if len(b64_data) == 0:
                self.request.sendall(b"No data received\n")
                return

            # Decode base64
            try:
                binary_data = base64.b64decode(b64_data.strip())
            except Exception:
                self.request.sendall(b"Invalid base64\n")
                return

            # Save to /chall/program
            with open("/chall/program", "wb") as f:
                f.write(binary_data)

            os.chmod("/chall/program", 0o755)

            # Get stop time and notify of runtime
            self.request.sendall(f"Running for {RUNTIME} seconds. Good luck!".encode())
            stop = time.time() + RUNTIME

            # Run with access to flag
            background = subprocess.Popen([
               "/chall/no-net", "timeout", "-k", str(TIMEOUT + 1), str(TIMEOUT), "landrun", "--rox", "/chall/program", "--ro", "/chall/flag.txt", "/chall/program"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Run without access to flag, capture stdout
            result = subprocess.run([
                "/chall/no-net", "timeout", "-k", str(TIMEOUT + 1), str(TIMEOUT), "landrun", "--rox", "/chall/program", "/chall/program"
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            # Wait for background process to finish as well
            background.wait()

            # Wait until stop time
            time.sleep(max(stop - time.time(), 0))

            self.request.sendall(b"\n=== Program output ===\n")
            self.request.sendall(result.stdout[:4096])  # limit output
            self.request.sendall(b"\n=== End ===\n")

        except Exception as e:
            self.request.sendall(b"Server error.\n")
            print(f"Error: {e}")

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as server:
        print(f"[+] Server listening on port {PORT}")
        server.serve_forever()
