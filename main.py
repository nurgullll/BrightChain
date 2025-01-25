from blockchain import Blockchain
from gui import display_blockchain


def main():
    # Блокчейнді құру
    blockchain = Blockchain()

    # Блоктарды қосу
    blockchain.add_block("Block 1 data")
    blockchain.add_block("Block 2 data")

    # Блокчейнді көрсету
    display_blockchain(blockchain)


if __name__ == "__main__":
    main()


