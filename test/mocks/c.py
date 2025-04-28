import requests
import json

BSC_RPC_URL = "https://bsc-dataseed.binance.org/"

def get_block_by_number(block_number):
    x="7666a1ed7e9ac3b7efeda847d8721072b89207ea86d68ea8f0c1ff1b81bdd76c"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hex(block_number), True],
        "id": 1
    }
    response = requests.post(BSC_RPC_URL, json=payload)
    return response.json()

def get_average_gas_price(block):
    transactions = block['result']['transactions']
    if not transactions:
        return 0
    total_gas_price = sum(int(tx['gasPrice'], 16) for tx in transactions)
    return total_gas_price / len(transactions) / 1e9  # Convert to Gwei

latest_block_number = int(requests.post(BSC_RPC_URL, json={
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
}).json()['result'], 16)

for i in range(100):
    block_number = latest_block_number - i
    block = get_block_by_number(block_number)
    avg_gas_price = get_average_gas_price(block)
    print(f"Block {block_number}: Average Gas Price = {avg_gas_price:.9f} Gwei")