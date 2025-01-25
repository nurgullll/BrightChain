import tkinter as tk
from blockchain import Blockchain

def display_blockchain(blockchain):
    window = tk.Tk()
    window.title("Blockchain Explorer")

    # Блок тізімін көрсету
    for i, block in enumerate(blockchain.chain):
        tk.Label(window, text=f"Block {i}").grid(row=i, column=0)
        tk.Label(window, text=f"Hash: {block.hash}").grid(row=i, column=1)
        tk.Label(window, text=f"Timestamp: {block.timestamp}").grid(row=i, column=2)
        tk.Label(window, text=f"Data: {block.data}").grid(row=i, column=3)

    # Блоктың жарамдылығын тексеру
    if not blockchain.is_chain_valid():
        tk.Label(window, text="Blockchain is INVALID!", fg="red").grid(row=len(blockchain.chain), column=0,
                                                                       columnspan=4)

    window.mainloop()
