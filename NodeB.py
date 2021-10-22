from Crypto.Cipher import AES

def decrypt_block(block, key):
    aes = AES.new(key, AES.MODE_ECB)
    decrypted_block = aes.decrypt(block)
    return decrypted_block


def decrypt_ECB(ciphertext, key):
    plaintext = []

    for i in ciphertext:
        text = decrypt_block(i, key)
        plaintext.append(text)

    text = ""
    for x in plaintext:
        text = text + (''.join(chr(i) for i in x))
    return text

def xorb(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def cbc_decrypt(ciphertext, key, IV):
    aes = AES.new(key, AES.MODE_CBC)
    cipher_blocks = []

    for i in range(len(ciphertext) // 16):
        cipher_blocks.append(ciphertext[i * 16:(i + 1) * 16])

    message_blocks = []

    message_blocks.append(xorb(aes.decrypt(cipher_blocks[0]), IV))

    for i in range(1, (len(ciphertext) // 16)):
        message_blocks.append(xorb(aes.decrypt(cipher_blocks[i]), cipher_blocks[i - 1]))


    pad_length = 16 - (len(ciphertext) % 16)

    if pad_length == 16:
        message_blocks.pop(int(len(ciphertext)) // 16 - 1)
    else:
        message_blocks[len(ciphertext) // 16 - 1] = message_blocks[len(ciphertext) // 16 - 1][
                                                    :len(ciphertext) // 16 - 1 - pad_length]

    message = ""
    for block in message_blocks:
        message = message + (''.join(chr(i) for i in block))

    return message.encode()