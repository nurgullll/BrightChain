import time
import tkinter as tk


# Қарапайым хэш алгоритмі (XOR негізінде)
def simple_hash(input_data):
    hash_value = 0
    for byte in input_data.encode('utf-8'):
        hash_value ^= byte
    return hex(hash_value)


# Блок Класы: Блок мәліметтері және хэштеу мен тексеру әдістері
class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Барлық блоктың мәліметтерін біріктіріп хэш жасаймыз
        block_string = f"{self.index}{self.timestamp}{self.data}{self.prev_hash}"
        return simple_hash(block_string)


# Генезис Блок (Блокчейннің бірінші блогы)
genesis_block = Block(0, time.time(), "Генезис Блок", "0")
print(f"Генезис Блок Хэші: {genesis_block.hash}")


# Блокчейн Класы: Блоктарды басқару және оларды қосу
class Blockchain:
    def __init__(self):
        self.chain = [genesis_block]

    def add_block(self, block):
        self.chain.append(block)

    def validate_chain(self):
        # Блокчейнді тексеру: әр блоктың алдыңғы хэші алдыңғы блоктың хэшіне сәйкес келуі керек
        for i in range(1, len(self.chain)):
            if self.chain[i].prev_hash != self.chain[i - 1].hash:
                return False
        return True


# Блокчейнді жасау
blockchain = Blockchain()

# Қолмен блок қосу
block_1 = Block(1, time.time(), "Блок #1 Мәліметтері", blockchain.chain[-1].hash)
blockchain.add_block(block_1)

# Блокчейнді тексеру
print("Блокчейнді тексеру:", blockchain.validate_chain())


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
        # Әр блоктың мәліметтерін көрсету
        self.block_info_label = tk.Label(self, text="", anchor="w", justify=tk.LEFT)
        self.block_info_label.pack(pady=10)

        # Блоктарды көрсету
        self.update_display()

    def update_display(self):
        # Блокчейннің мәліметтерін көрсету
        block_info = ""
        for block in self.blockchain.chain:
            block_info += f"Блок {block.index}:\nХэш: {block.hash}\nУақыт таңбасы: {block.timestamp}\nМәліметтер: {block.data}\n\n"

        self.block_info_label.config(text=block_info)


# GUI-ді іске қосу
app = BlockchainExplorer(blockchain)
app.mainloop()
