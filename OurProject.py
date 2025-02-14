import time
import tkinter as tk
import rsa
import hashlib
import json
from flask import Flask, jsonify, request
from tkinter import messagebox


# Қарапайым хэш алгоритмі (XOR негізінде)
def simple_hash(input_data):
    hash_value = 0
    for byte in input_data.encode('utf-8'):
        hash_value ^= byte
    return hex(hash_value)


# Меркл ағашының тамырын есептейтін функция
def calculate_merkle_root(transactions):
    if not transactions:
        return "0"

    while len(transactions) > 1:
        # Егер транзакция саны тақ болса, соңғы элементті қайтадан қосамыз
        if len(transactions) % 2 != 0:
            transactions.append(transactions[-1])

        # Жұп-жұп хэштерді біріктіріп жаңа хэштерді есептейміз
        transactions = [simple_hash(transactions[i] + transactions[i + 1]) for i in range(0, len(transactions), 2)]

    return transactions[0]  # Соңғы қалған хэш - Меркл рут


# Түйін (Node) құрылымы
class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.blockchain = Blockchain()
        self.peers = []  # Байланысты түйіндер

    def connect_peer(self, peer):
        self.peers.append(peer)

    def broadcast_block(self, block):
        for peer in self.peers:
            peer.receive_block(block)

    def receive_block(self, block):
        if self.blockchain.validate_block(block):
            self.blockchain.add_block(block)


# Транзакция Класы: Транзакция мәліметтерін сақтайды
class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = time.time()
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self):
        # Транзакция хэшін жасау: жіберуші, алушы, сома және уақыт таңбасы бойынша
        tx_string = f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"
        return simple_hash(tx_string)


class Wallet:
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)  # RSA кілттерін генерациялау
        self.balance = 100
        self.address = self.get_address_from_public_key()  # Ашық кілттің хэшін аккаунт адресі ретінде қолдану

    def get_address_from_public_key(self):
        """Ашық кілттің хэшін алу (аккаунт адресі ретінде қолдану)"""
        public_key_bytes = self.public_key.save_pkcs1()  # Ашық кілтті байттар түрінде алу
        public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()  # Хэштеу
        return public_key_hash

    def sign_transaction(self, transaction_data):
        """Сандық қолтаңба жасау"""
        return rsa.sign(transaction_data.encode(), self.private_key, 'SHA-1')

    def verify_transaction(self, transaction_data, signature, sender_public_key):
        """Транзакцияның шынайылығын тексеру"""
        try:
            return rsa.verify(transaction_data.encode(), signature, sender_public_key)
        except rsa.VerificationError:
            return False

    def encrypt_data(self, data):
        """Ашық кілтпен мәліметтерді шифрлау"""
        return rsa.encrypt(data.encode(), self.public_key)

    def decrypt_data(self, encrypted_data):
        """Жеке кілтпен мәліметтерді дешифрлау"""
        try:
            return rsa.decrypt(encrypted_data, self.private_key).decode()
        except rsa.DecryptionError:
            return "Дешифрлау қатесі"


# Блок Класы: Блок мәліметтері және хэштеу мен тексеру әдістері
class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.transactions = []  # Транзакциялар тізімі
        self.merkle_root = "0"  # Меркл рут бастапқыда 0 деп беріледі
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Барлық блоктың мәліметтерін біріктіріп хэш жасаймыз
        block_string = f"{self.index}{self.timestamp}{self.data}{self.prev_hash}{self.merkle_root}"
        return simple_hash(block_string)

    def add_transaction(self, transaction):
        self.transactions.append(transaction)
        # Транзакция қосылғаннан кейін Меркл рутты қайта есептеу
        self.merkle_root = calculate_merkle_root([tx.tx_hash for tx in self.transactions])
        # Блоктың хэшін қайта есептеу
        self.hash = self.calculate_hash()


# Генезис Блок (Блокчейннің бірінші блогы)
genesis_block = Block(0, time.time(), "Генезис Блок", "0")
print(f"Генезис Блок Хэші: {genesis_block.hash}")


# Блокчейн Класы: Блоктарды басқару және оларды қосу
class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        # Бірінші блокты құру
        self.create_block(previous_hash='1', proof=100)

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.transactions,
            'proof': proof,
            'previous_hash': previous_hash
        }
        # Жаңа блок қосылғаннан кейін, транзакциялар тізімін босату
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        # Proof of work алгоритмін орындау
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })
        # Транзакция қосылған соң, келесі блок индексі қайтарылады
        return self.get_previous_block()['index'] + 1


app = Flask(__name__)


@app.route('/')
def home():
    return "Welcome to the Blockchain Server!"  # Негізгі бет


@app.route('/blockchain')
def blockchain():
    return "Blockchain functionality will go here."


app.config['DEBUG'] = True  # Даму режимін қосу

# Блокчейнді жасау
blockchain = Blockchain()


# 4
@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)

    # Транзакция қосу
    blockchain.add_transaction(sender="0", receiver="node_address", amount=1)

    # Жаңа блокты жасау
    block = blockchain.create_block(proof, previous_hash)
    response = {
        'message': 'Түйін жаңа блокты қосты',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash']
    }
    return jsonify(response), 200


@app.route('/send_transaction', methods=['POST'])
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


@app.route('/explorer', methods=['GET'])
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


# Блоктарды көрсету үшін API қосу
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


# Блокчейн Құрастырушысын GUI арқылы көрсету
class BlockchainExplorer(tk.Tk):
    def __init__(self, blockchain):
        super().__init__()
        self.blockchain = blockchain
        self.title("Блокчейн Көрсетуші")
        self.geometry("600x600")

        # GUI компоненттерін жасау
        self.create_widgets()

    def create_widgets(self):
        # Әр блоктың және транзакцияның мәліметтерін көрсету
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

        # Блокчейнді тексеру үшін батырма
        self.validate_button = tk.Button(self, text="Блокчейнді тексеру", command=self.validate_blockchain)
        self.validate_button.pack(pady=10)

    def add_transaction(self):
        # Пайдаланушының енгізу өрістерінен транзакция мәліметтерін алу
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

            # Транзакцияны қосқаннан кейін жаңа блок жасау
            self.blockchain.create_new_block(f"Блок {len(self.blockchain.chain)} Мәліметтері")

            # Енгізу өрістерін тазалау
            self.sender_entry.delete(0, tk.END)
            self.receiver_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)

            # GUI-ді жаңарту: жаңа блок және транзакция мәліметтерін көрсету
            self.update_display()

    def validate_blockchain(self):
        # Блокчейннің дұрыстығын тексеру
        is_valid = self.blockchain.validate_chain()
        if is_valid:
            result_text = "Блокчейн дұрыс!"
        else:
            result_text = "Блокчейнде қателер бар!"

        # Нәтижені көрсету
        self.block_info_label.config(text=result_text)

    def update_display(self):
        # Блокчейннің жаңартылған мәліметтерін көрсету
        block_info = ""
        for block in self.blockchain.chain:
            block_info += f"Блок {block.index}:\nХэш: {block.hash}\nУақыт таңбасы: {block.timestamp}\nМәліметтер: {block.data}\n"
            block_info += f"Меркл Рут: {block.merkle_root}\n"
            for tx in block.transactions:
                block_info += f"  Транзакция Хэші: {tx.tx_hash}\n  Жіберуші: {tx.sender}\n  Алушы: {tx.receiver}\n  Сома: {tx.amount}\n  Уақыт таңбасы: {tx.timestamp}\n\n"

        self.block_info_label.config(text=block_info)


class WalletGUI:
    def __init__(self, root):
        self.wallet = Wallet()
        self.root = root
        self.root.title("Әмиян")

        # Баланс көрсету
        self.balance_label = tk.Label(root, text=f"Баланс: {self.wallet.balance} BTC", font=("Arial", 14))
        self.balance_label.pack()

        # Ашық кілт немесе адрес
        self.address_label = tk.Label(root, text=f"Ашық кілт (Адрес): {self.wallet.address}")
        self.address_label.pack()

        # Алушының аты
        self.receiver_label = tk.Label(root, text="Алушының аты:")
        self.receiver_label.pack()
        self.receiver_entry = tk.Entry(root)
        self.receiver_entry.pack()

        # Сома
        self.amount_label = tk.Label(root, text="Сома:")
        self.amount_label.pack()
        self.amount_entry = tk.Entry(root)
        self.amount_entry.pack()

        # Жіберу батырмасы
        self.send_button = tk.Button(root, text="Жіберу", command=self.send_transaction)
        self.send_button.pack()

    def send_transaction(self):
        """Транзакция жасау және шифрлау"""
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

        # Верификация жасау (өзіне тексеру)
        if self.wallet.verify_transaction(transaction_data, signature, self.wallet.public_key):

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


# GUI-ді іске қосу
if __name__ == "__main__":
    root = tk.Tk()
    gui = WalletGUI(root)
    root.mainloop()
    app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)
app = BlockchainExplorer(blockchain)
app.mainloop()
