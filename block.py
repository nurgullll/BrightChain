import time
from custom_hash import custom_hash


class Block:
    def __init__(self, data, previous_hash):
        self.timestamp = time.time()  # Уақыт таңбасы
        self.data = data  # Блоктың деректері
        self.previous_hash = previous_hash  # Алдыңғы блоктың хэші
        self.hash = self.calculate_hash()  # Блоктың өз хэші

    def calculate_hash(self):
        raw_data = f"{self.timestamp}{self.data}{self.previous_hash}"
        return custom_hash(raw_data)

    def _repr_(self):
        return f"Block(Hash: {self.hash}, Data: {self.data}, Timestamp: {self.timestamp})"

