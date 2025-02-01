
import time
import tkinter as tk

# Қарапайым хэш алгоритмі (XOR негізінде)
def simple_hash(input_data):
    hash_value = 0
    for byte in input_data.encode('utf-8'):
        hash_value ^= byte
    return hex(hash_value)

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

# Блок Класы: Блок мәліметтері және хэштеу мен тексеру әдістері
class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()
        self.transactions = []  # Транзакциялар тізімі

    def calculate_hash(self):
        # Барлық блоктың мәліметтерін біріктіріп хэш жасаймыз
        block_string = f"{self.index}{self.timestamp}{self.data}{self.prev_hash}"
        return simple_hash(block_string)

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

# Генезис Блок (Блокчейннің бірінші блогы)
genesis_block = Block(0, time.time(), "Генезис Блок", "0")
print(f"Генезис Блок Хэші: {genesis_block.hash}")

# Блокчейн Класы: Блоктарды басқару және оларды қосу
class Blockchain:
    def __init__(self):
        self.chain = [genesis_block]
        self.pending_transactions = []  # Қосылатын транзакциялардың тізімі

    def add_block(self, block):
        self.chain.append(block)

    def create_new_block(self, data):
        # Жаңа блок құрып, барлық күтіп тұрған транзакцияларды оған қосу
        last_block = self.chain[-1]
        new_block = Block(len(self.chain), time.time(), data, last_block.hash)
        for tx in self.pending_transactions:
            new_block.add_transaction(tx)
        self.add_block(new_block)
        self.pending_transactions = []  # Транзакциялар тізімін тазалау
        return new_block  # Жаңа блокты қайтарамыз

    def add_pending_transaction(self, transaction):
        # Күтіп тұрған транзакцияны қосу
        self.pending_transactions.append(transaction)

    def validate_chain(self):
        # Блокчейнді тексеру: әр блоктың алдыңғы хэші алдыңғы блоктың хэшіне сәйкес келуі керек
        for i in range(1, len(self.chain)):
            if self.chain[i].prev_hash != self.chain[i - 1].hash:
                return False
        return True

# Блокчейнді жасау
blockchain = Blockchain()

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

    def update_display(self):
        # Блокчейннің жаңартылған мәліметтерін көрсету
        block_info = ""
        for block in self.blockchain.chain:
            block_info += f"Блок {block.index}:\nХэш: {block.hash}\nУақыт таңбасы: {block.timestamp}\nМәліметтер: {block.data}\n"
            for tx in block.transactions:
                block_info += f"  Транзакция Хэші: {tx.tx_hash}\n  Жіберуші: {tx.sender}\n  Алушы: {tx.receiver}\n  Сома: {tx.amount}\n  Уақыт таңбасы: {tx.timestamp}\n\n"

        self.block_info_label.config(text=block_info)

# GUI-ді іске қосу
app = BlockchainExplorer(blockchain)
app.mainloop()