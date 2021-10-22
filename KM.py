import NodeA
import NodeB
import os
from Crypto.Cipher import AES

key = os.urandom(16)
print(key)
key_prim = os.urandom(16)
print(key_prim)
IV=os.urandom(16)
mode = input("Enter the mode")

a = NodeA
b = NodeB


def enc_key():
    if mode == "CBC":
        crypt = AES.new(key_prim, AES.MODE_CBC)
        encrypt_key = crypt.encrypt(key)
    else:
        crypt = AES.new(key_prim, AES.MODE_ECB)
        encrypt_key = crypt.encrypt(key)
    return encrypt_key
def dec_key(Enc_key,key_prim):
    if mode == "CBC":
        decrypt = AES.new(key_prim, AES.MODE_CBC)
        decrypted_key = decrypt.decrypt(Enc_key)
    else:
        decrypt = AES.new(key_prim, AES.MODE_ECB)
        decrypted_key = decrypt.encrypt(Enc_key)
    return decrypted_key

A_cheie = enc_key()
B_cheie=dec_key(A_cheie,key_prim)

plaintext=input("Ce text doriti sa codati: ")
if mode=="CBC":
    encrypted=a.cbc_encrypt(plaintext,B_cheie,IV)
    print("Textul criptat este")
    print(encrypted)
    decrypted=b.cbc_decrypt(encrypted,B_cheie,IV)
    print("Textul decriptat este")
    print(decrypted)
else:
    encrypted=a.encrypt_ECB(plaintext,B_cheie)
    print("Textul criptat este")
    print(encrypted)
    decrypted=b.decrypt_ECB(encrypted,B_cheie)
    print("Textul decriptat este")
    print(decrypted)




