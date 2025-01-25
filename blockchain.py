from block import Block

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]  # Блокчейнді бастау үшін Генезис блок
        self.difficulty = 2  # Мысал ретінде, ауырлық дәрежесі

    def create_genesis_block(self):
        return Block("Genesis Block", "0")

    def add_block(self, data):
        previous_block = self.chain[-1]  # Соңғы блокты аламыз
        new_block = Block(data, previous_block.hash)  # Жаңа блокты қосамыз
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            if current.previous_hash != previous.hash:
                return False
            if current.hash != current.calculate_hash():  # Блоктың өз хэші тексеріледі
                return False
        return True

    def __repr__(self):
        return f"Blockchain({len(self.chain)} blocks)"

