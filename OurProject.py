import threading
import time
import tkinter as tk
import requests
import rsa
import hashlib
import random
import json
from flask import Flask, jsonify, request
from tkinter import messagebox
import multiprocessing

# Хэш функциясын анықтау
"""def calculate_block_hash1(index, timestamp, transactions, previous_hash, nonce):
    block_string = f"{index}{timestamp}{transactions}{previous_hash}{nonce}"
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest() """


# Қарапайым хэш
def simple_hash(input_data):
    hash_value = 0
    for byte in input_data.encode('utf-8'):
        hash_value ^= byte
    return hex(hash_value)


def calculate_merkle_root(transactions1):
    if not transactions1:
        return "0"

    while len(transactions1) > 1:
        if len(transactions1) % 2 != 0:
            transactions1.append(transactions1[-1])
        transactions1 = [simple_hash(transactions1[i] + transactions1[i + 1]) for i in range(0, len(transactions1), 2)]

    return transactions1[0]


def miner_process(self, miner_address):
    max_blocks = 10
    mined_blocks = 0

    while mined_blocks < max_blocks:
        if self.pending_transactions:
            new_block = self.mine_pending_transactions(miner_address)
            print(f"Miner {miner_address} mined Block {new_block.index}!")
            mined_blocks += 1
        time.sleep(random.randint(2, 5))

    # Түйін (Node) құрылымы


class Node(multiprocessing.Process):
    def __init__(self, node_id, difficulty1, queue):
        super().__init__()
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty1)
        self.peers = []
        self.queue = queue  # Кезек арқылы байланысу

    def connect_peer(self, peer):
        self.peers.append(peer)

    def broadcast_block(self, block):
        for peer in self.peers:
            peer.receive_block(block)

    def receive_block(self, block):
        if self.blockchain.validate_block(block):
            self.blockchain.add_block(block)

    def run(self, block=None):
        """Процесс ретінде түйінді іске қосу"""
        while True:
            if not self.queue.empty():
                transaction = self.queue.get()
                print(f"Түйін {self.node_id}: жаңа транзакция алды - {transaction}")
                self.blockchain.add_transaction(transaction, amount=0, fee=0, recipient=0)

            time.sleep(5)  # Тауып жатқандай етіп күту
            self.blockchain.mine_block()
            self.broadcast_block(block)
            print(f"Түйін {self.node_id}: жаңа блок тапты")


class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = time.time()
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self):
        tx_string = f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_string.encode()).hexdigest()


def verify_transaction(transaction_data, signature, sender_public_key):
    """Транзакцияның шынайылығын тексеру"""
    try:
        return rsa.verify(transaction_data.encode(), signature, sender_public_key)
    except rsa.VerificationError:
        return False


class Wallet:
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)  # RSA кілттерін генерациялау
        self.balance = 100
        self.address = self.get_address_from_public_key()  # Ашық кілттің хэшін аккаунт адресі ретінде қолдану

    def get_address_from_public_key(self):
        """Ашық кілттің хэшін алу (аккаунт адресі ретінде қолдану)"""
        public_key_bytes = self.public_key.save_pkcs1()  # Ашық кілтті байттар түрінде алу
        public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()  # Хэштеу
        return public_key_hash

    def sign_transaction(self, transaction_data):
        """Сандық қолтаңба жасау"""
        return rsa.sign(transaction_data.encode(), self.private_key, 'SHA-1')

    def encrypt_data(self, data):
        """Ашық кілтпен мәліметтерді шифрлау"""
        return rsa.encrypt(data.encode(), self.public_key)

    def verify_transaction(self, transaction_data, signature):
        """Транзакцияның қолтаңбасын тексеру"""
        try:
            rsa.verify(transaction_data.encode(), signature, self.public_key)
            return True
        except rsa.VerificationError:
            return False

    def decrypt_data(self, encrypted_data):
        """Жеке кілтпен мәліметтерді дешифрлау"""
        try:
            return rsa.decrypt(encrypted_data, self.private_key).decode()
        except rsa.DecryptionError:
            return "Дешифрлау қатесі"


# Блок Класы: Блок мәліметтері және хэштеу мен тексеру әдістері
class Block:
    def __init__(self, index1, timestamp1, transactions1, previous_hash1, nonce1, difficulty1):
        self.index = index1
        self.previous_hash = previous_hash1
        self.transactions = transactions1
        self.timestamp = timestamp1
        self.difficulty = difficulty1
        self.nonce = nonce1
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.transactions}{self.timestamp}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __repr__(self):
        return f"Block#{self.index} [Hash: {self.hash}]"

    def mine_block(self):
        """
        Mine the block by finding a nonce that results in a hash meeting the difficulty criteria.
        """
        self.nonce = 0
        computed_hash = self.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            self.nonce += 1
            computed_hash = self.compute_hash()
        return computed_hash


# Генезис Блок (Блокчейннің бірінші блогы)
genesis_transactions = []  # Транзакциялар тізімін бос деп алайық
genesis_block = Block(0, time.time(), "Генезис Блок", "0", 0, 3)

print(f"Генезис Блок Хэші: {genesis_block.hash}")


# Блокчейн Класы: Блоктарды басқару және оларды қосу
def calculate_block_hash(block):
    return hashlib.sha256(
        f"{block.index}{block.timestamp}{block.transactions}{block.previous_hash}{block.nonce}".encode()).hexdigest()


class Blockchain:
    def fork_resolution(self, new_chain):
        """ Егер жаңа тізбек біздікінен ұзын болса, оны қабылдаймыз """
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            print("⛓ Fork detected! Switching to the longest chain.")
        else:
            print("❌ New chain rejected. Keeping the current chain.")

    def __init__(self, difficult, mining_reward=50):  # Жүлде мөлшерін параметр ретінде қосу
        self.block_info_label = []
        self.chain = []
        self.current_transactions = []
        self.difficult = difficult
        self.mining_reward = mining_reward  # Жүлде мөлшерін анықтау
        self.pending_transactions = []
        self.nodes = set()
        self.create_genesis_block()

    def resolve_conflicts(self):
        """
        Resolve conflicts by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.valid_chain():
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def valid_chain(self):
        """ Блокчейннің жарамдылығын тексеру """
        for i in range(1, len(self.chain)):
            prev_block = self.chain[i - 1]
            curr_block = self.chain[i]

            if curr_block.previous_hash != prev_block.hash:
                return False  # Блоктардың байланысы дұрыс емес

            if curr_block.hash != curr_block.compute_hash():
                return False  # Блоктың хэші дұрыс емес

        return True  # Барлық блоктар дұрыс

    def create_genesis_block(self):
        # Генезис блокты жасау
        genesis_block1 = Block(0, time.time(), "Genesis Block", "0", 0, 3)
        genesis_block1.mine_block()
        self.chain.append(genesis_block1)

    def mine_pending_transactions(self, miner_address):
        block = Block(len(self.chain), self.chain[-1].hash, self.pending_transactions, time.time(), 0, 2)
        block.mine_block()
        self.chain.append(block)
        reward_transaction = {
            'sender': 'Network',
            'recipient': miner_address,
            'amount': self.mining_reward + sum(tx['fee'] for tx in self.pending_transactions),
            'fee': 0
        }
        self.pending_transactions = [reward_transaction]
        return block

    def mine_block(self):
        last_block = self.chain[-1]
        nonce1 = self.proof_of_work(last_block)

        reward_transaction = {"sender": "system", "recipient": "miner", "amount": self.mining_reward}
        self.current_transactions.append(reward_transaction)  # Жүлде транзакциясы

        # ✅ Дұрыс аргументтермен `Block` объектісін жасау
        block = Block(len(self.chain), time.time(), last_block.hash, self.current_transactions, nonce1, 3)

        self.chain.append(block)
        self.current_transactions = []  # Жаңа транзакциялар қабылдауға дайын болу үшін тазалау
        mined_hash = genesis_block.mine_block()
        print(f"Майненген Генезис Блок Хэші: {mined_hash}")

    def create_block(self, proof, previous_hash1):
        block = Block(len(self.chain), previous_hash1, self.pending_transactions, self.difficult,
                      proof, 3)  # 🔹 'nonce' ретінде 'proof' беріледі
        self.chain.append(block)
        self.pending_transactions = []  # Күтілетін транзакцияларды тазалау
        return block

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block()
        self.chain.append(new_block)

    @staticmethod
    def hash(block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    def add_transaction(self, sender, recipient, amount, fee):
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'fee': fee
        }
        self.pending_transactions.append(transaction)

    def proof_of_work(self, last_block):
        nonce1 = 0
        while not self.valid_proof(last_block, nonce1):
            nonce1 += 1
        return nonce1

    def validate_block(self, block):
        """Блоктың жарамдылығын тексеру"""
        last_block = self.get_latest_block()

        # Блоктың алдыңғы хэші соңғы блоктың хэшімен сәйкес келе ме?
        if block.previous_hash != last_block.hash:
            return False

        # Блоктың хэші дұрыс па?
        if block.hash != calculate_block_hash(block):
            return False

        return True

    def valid_proof(self, last_block, nonce1):
        guess = f"{last_block.hash}{nonce1}"
        guess_hash = hashlib.sha256(guess.encode()).hexdigest()
        return guess_hash[:self.difficult] == "0" * self.difficult

    def get_latest_block(self):
        return self.chain[-1]

    # Минер функциясы
    @staticmethod
    def miner_process(blockchain1):
        while True:
            # Attempt to mine a new block
            new_block = blockchain1.mine_block()
            if new_block:
                print(f"Miner mined a new block")
            # Sleep to simulate time between mining attempts
            time.sleep(1)


# Flask серверін жасау
app1 = Flask(__name__)


@app1.route('/')
def home():
    return "Welcome to the Blockchain Server!"  # Негізгі бет


@app1.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


app1.config['DEBUG'] = True  # Даму режимін қосу


# 4
@app1.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof_of_work']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hashh = blockchain.hash(previous_block)

    # Миннингке сыйақы қосу
    blockchain.add_transaction(sender="0",
                               amount=0, fee=0, recipient=0)

    block = blockchain.create_block(proof, previous_hashh)
    response = {
        'message': 'Түйін жаңа блокты қосты',
        'index': block.index,
        'timestamp': block.timestamp,
        'transactions': block.transactions,
        'previous_hash': block.previous_hash
    }

    return jsonify(response), 200


# GUI және Flask серверін бірге іске қосу үшін
def run_flask():
    app = Flask(__name__)

    @app1.route('/')
    def index1():
        return "Blockchain Node Active"

    app.run(host='0.0.0.0', port=5001)


@app1.route('/send_transaction', methods=['POST'])
def send_transaction():
    data = request.get_json()

    # Деректерді тексеру
    if 'sender' not in data or 'receiver' not in data or 'amount' not in data:
        return jsonify({'error': 'Missing data'}), 400

    sender = data['sender']
    receiver = data['receiver']
    amount = data['amount']

    if amount <= 0:
        return jsonify({'error': 'Amount must be greater than 0'}), 400

    blockchain.add_transaction(sender, receiver, amount, 0)
    return jsonify({'message': f'Transaction will be added to Block '}), 201


@app1.route('/explorer', methods=['GET'])
def explorer():
    chain = blockchain.chain
    blocks_info = []

    for block in chain:
        blocks_info.append({
            'index': block['index'],
            'timestamp': block['timestamp'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash']
        })

    return jsonify(blocks_info), 200


# Блокчейн Құрастырушысын GUI арқылы көрсету

class BlockchainExplorer(tk.Tk):
    def __init__(self, blockchain1):
        super().__init__()
        self.block_info_label = None
        self.add_transaction_label = None
        self.sender_label = None
        self.sender_entry = None
        self.receiver_label = None
        self.receiver_entry = None
        self.amount_label = None
        self.amount_entry = None
        self.add_transaction_button = None
        self.validate_button = None
        self.blockchain = blockchain1
        self.title("Блокчейн Көрсетуші")
        self.geometry("600x600")

        self.create_widgets()

    def create_widgets(self):
        self.block_info_label = tk.Label(self, text="", anchor="w", justify=tk.LEFT)
        self.block_info_label.pack(pady=10)

        # Транзакция қосу үшін жапсырма
        self.add_transaction_label = tk.Label(self, text="Транзакция мәліметтерін енгізіңіз:")
        self.add_transaction_label.pack(pady=10)

        # Жіберуші, Алушы және Сома үшін енгізу өрістері
        self.sender_label = tk.Label(self, text="Жіберуші:")
        self.sender_label.pack()
        self.sender_entry = tk.Entry(self)
        self.sender_entry.pack()

        self.receiver_label = tk.Label(self, text="Алушы:")
        self.receiver_label.pack()
        self.receiver_entry = tk.Entry(self)
        self.receiver_entry.pack()

        self.amount_label = tk.Label(self, text="Сома:")
        self.amount_label.pack()
        self.amount_entry = tk.Entry(self)
        self.amount_entry.pack()

        # Транзакцияны қосу үшін батырма
        self.add_transaction_button = tk.Button(self, text="Транзакция қосу", command=self.add_transaction)
        self.add_transaction_button.pack(pady=20)

        # Блокчейнді тексеру үшін батырма

    def add_transaction(self):
        # Пайдаланушының енгізу өрістерінен транзакция мәліметтерін алу
        sender = self.sender_entry.get()
        receiver = self.receiver_entry.get()
        try:
            amount = float(self.amount_entry.get())
        except ValueError:
            amount = 0  # Егер енгізу дұрыс болмаса, 0 деп аламыз

        if sender and receiver and amount > 0:
            # Транзакцияны жасап, оны күтіп тұрған транзакциялар тізіміне қосу
            transaction = Transaction(sender, receiver, amount)
            self.blockchain.add_pending_transaction(transaction)

            # Транзакцияны қосқаннан кейін жаңа блок жасау
            self.blockchain.create_new_block(f"Блок {len(self.blockchain.chain)} Мәліметтері")

            # Енгізу өрістерін тазалау
            self.sender_entry.delete(0, tk.END)
            self.receiver_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)

            # GUI-ді жаңарту: жаңа блок және транзакция мәліметтерін көрсету
            self.update_display()

    def update_display(self):
        # Блокчейннің жаңартылған мәліметтерін көрсету
        block_info = ""
        for block in self.blockchain.chain:
            block_info += f"Блок {block.index}:\nХэш: {block.hash}\nУақыт таңбасы: {block.timestamp}\nМәліметтер: {block.data}\n"
            block_info += f"Меркл Рут: {block.merkle_root}\n"
            for tx in block.transactions:
                block_info += f"  Транзакция Хэші: {tx.tx_hash}\n  Жіберуші: {tx.sender}\n  Алушы: {tx.receiver}\n  Сома: {tx.amount}\n  Уақыт таңбасы: {tx.timestamp}\n\n"

        self.block_info_label.config(text=block_info)


class WalletGUI:
    def __init__(self, root1):
        self.wallet = Wallet()
        self.root = root1
        self.root.title("Әмиян")

        # Display balance
        self.balance_label = tk.Label(root, text=f"Баланс: {self.wallet.balance} BTC", font=("Arial", 14))
        self.balance_label.pack()

        # Display public key (address)
        self.address_label = tk.Label(root, text=f"Ашық кілт (Адрес): {self.wallet.address}")
        self.address_label.pack()

        # Recipient's name
        self.receiver_label = tk.Label(root, text="Алушының аты:")
        self.receiver_label.pack()
        self.receiver_entry = tk.Entry(root)
        self.receiver_entry.pack()

        # Amount
        self.amount_label = tk.Label(root, text="Сома:")
        self.amount_label.pack()
        self.amount_entry = tk.Entry(root)
        self.amount_entry.pack()

        # Send button
        self.send_button = tk.Button(root, text="Жіберу", command=self.send_transaction)
        self.send_button.pack()

    def send_transaction(self):
        """Create and encrypt a transaction"""
        receiver = self.receiver_entry.get()
        amount = self.amount_entry.get()

        if not receiver or not amount.isdigit():
            messagebox.showerror("Қате", "Дұрыс ақпарат енгізіңіз!")
            return

        amount = int(amount)
        if amount > self.wallet.balance:
            messagebox.showerror("Қате", "Жеткілікті қаражат жоқ!")
            return

        transaction_data = f"{receiver} {amount} BTC"
        signature = self.wallet.sign_transaction(transaction_data)

        # Verify the transaction (self-verification)
        if self.wallet.verify_transaction(transaction_data, signature):
            encrypted_transaction = self.wallet.encrypt_data(transaction_data)
            decrypted_transaction = self.wallet.decrypt_data(encrypted_transaction)

            if decrypted_transaction == transaction_data:
                self.wallet.balance -= amount
                self.balance_label.config(text=f"Баланс: {self.wallet.balance} BTC")
                messagebox.showinfo("Транзакция", "Транзакция сәтті орындалды!")
            else:
                messagebox.showerror("Қате", "Шифрлау қатесі!")
        else:
            messagebox.showerror("Қате", "Транзакция расталмады!")


if __name__ == "__main__":
    # Start the Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Initialize the blockchain
    blockchain = Blockchain(difficult=3)

    # Add transactions with fees
    blockchain.add_transaction("Alice", "Bob", 10, fee=2)
    blockchain.add_transaction("Charlie", "Dave", 30, fee=3)

    # Start miner processes
    miner1 = multiprocessing.Process(target=miner_process, args=(blockchain, "Miner1"))
    miner2 = multiprocessing.Process(target=miner_process, args=(blockchain, "Miner2"))

    miner1.start()
    miner2.start()

    print("Blockchain is valid:", blockchain.valid_chain())

    # Start the Tkinter GUI

    root = tk.Tk()
    gui = WalletGUI(root)
    root.mainloop()
