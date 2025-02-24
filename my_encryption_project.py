from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def generate_key():
    """Генерация случайного ключа."""
    return os.urandom(32)  # 32 байта для AES-256

def encrypt(plaintext, key):
    """Шифрование текста с использованием AES в режиме CBC."""
    iv = os.urandom(16)  # Вектор инициализации
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Дополнение данных до блока
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Возвращаем IV вместе с зашифрованными данными

def decrypt(ciphertext, key):
    """Расшифрование текста с использованием AES в режиме CBC."""
    iv = ciphertext[:16]  # Извлечение IV
    actual_ciphertext = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()  # Исправлено имя переменной

    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Удаление дополнения
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext

# Пример использования
if __name__ == "__main__":
    key = generate_key()
    plaintext = b"Zdravstvyite damy i gospoda menya zovyt Alexey Frolov, ya moshennik "
    
    print("Original:", plaintext)

    encrypted = encrypt(plaintext, key)
    print("Encrypted:", encrypted)

    decrypted = decrypt(encrypted, key)
    print("Decrypted:", decrypted)
