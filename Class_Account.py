from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512

class KeyPair:
    def genKeyPair(self):
        privatekey = RSA.generate(1024)
        publickey = privatekey.publickey()
        self.privatekey = privatekey.exportKey(format='PEM')
        self.publickey = publickey.exportKey(format='PEM')
        return self.publickey, self.privatekey

    def __init__(self):
        self.publickey, self.privatekey = self.genKeyPair()

    def printKeyPair(self):
        print(f'PublicKey = {self.publickey}, PrivateKey = {self.privatekey}')

    def __str__(self):
        return str(self.publickey) + " " + str(self.privatekey)


class Signature:
    def signData(self, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):

        signer = PKCS1_v1_5.new(RSA.importKey(key))
        hash_value = hash_algorithm.new(plaintext)
        return signer.sign(hash_value)

    def verifySignature(self, sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):

        hash_value = hash_algorithm.new(plaintext)
        verifier = PKCS1_v1_5.new(RSA.importKey(key))
        return verifier.verify(hash_value, sign)

    def printSignature(self):
        print(self.signature)


class Account:
    def __init__(self):
        self.genAccount()

    def genAccount(self):
        A = KeyPair()
        self.wallets = []
        self.wallets.append(A.genKeyPair())
        self.accountID = self.wallets[0]
        return self.wallets, self.accountID

    def addKeyPairToWallet(self):
        self.wallets.append(A.genKeyPair())

    def signtext(self,text, index):
        B = Signature()
        key = self.wallets[index][1]
        return B.signData(text, key)


A = Signature()
privatekey = RSA.generate(1024)
publickey = privatekey.publickey()
privatekey = privatekey.exportKey(format='PEM')
publickey = publickey.exportKey(format='PEM')
B = Account()
B.genAccount()
message = "qwertyu"
signature = B.signtext(message.encode(encoding='utf-8'), 0)
result = A.verifySignature(signature, message.encode('utf-8'), B.wallets[0][0])
print(result)