
from Crypto.Cipher import AES


def check_length(messsage):
    if len(messsage) % 16 == 0:
        return messsage
    else:
        padding_len = 16 - (len(messsage) % 16)
        padding = ""
        for i in range(padding_len):
            padding += "0"
        return messsage + padding


def encrypt_block(block, key):
    aes = AES.new(key, AES.MODE_ECB)
    encrypted_block = aes.encrypt(block.encode())
    return encrypted_block




def encrypt_ECB(plaintext, key):
    plaintext = check_length(plaintext)
    blocks = []
    encrypted = []
    for i in range(len(plaintext)//16):
        blocks.append(plaintext[i * 16:(i + 1) * 16])
    for i in blocks:
        ciphertext = encrypt_block(i, key)
        encrypted.append(ciphertext)
    return encrypted


def xorb(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def cbc_encrypt(plaintext, key, IV):
    plaintext = check_length(plaintext)
    blocks_message = []
    for i in range(len(plaintext) // 16):
        blocks_message.append(plaintext[i * 16:(i + 1) * 16])
    aes = AES.new(key, AES.MODE_CBC)
    cipher_blocks = []
    cipher_blocks.append(aes.encrypt(xorb(IV, blocks_message[0].encode())))
    for i in range(1, len(plaintext) // 16):
        cipher_blocks.append(aes.encrypt(xorb(cipher_blocks[i - 1], blocks_message[i])))

    cipher = ''

    for block in cipher_blocks:
        cipher += ''.join([chr(i) for i in block])
    return cipher.encode()




