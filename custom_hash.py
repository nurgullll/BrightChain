def custom_hash(data):
    hash_value = 0
    for char in data:
        hash_value = (hash_value * 31 + ord(char)) % (10**8)
    return hash_value

# Функцияны шақырып, нәтиже шығару
data = "Hello, Blockchain!"  # Берілген деректер
hash_result = custom_hash(data)
print("Hash Value:", hash_result)