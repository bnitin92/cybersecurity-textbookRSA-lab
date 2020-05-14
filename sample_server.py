import argparse
import os
import socket
from time import sleep
from rsa import RSACipher
from aes import AESCipher


def getSessionKey(rsa, cipher):
    """
    Get the AES session key be decrypting the RSA ciphertext
    """
    try:
        AESEncrypted = cipher[:256]
        AESKey = rsa.decrypt(AESEncrypted)
        return AESKey[(len(AESKey)-32):]
    except ValueError:
        return False


def myDecrypt(rsa, cipher):
    """
    Decrypt the client message:
    AES key encrypted by the
    public RSA key of the server + message encrypted by the AES key
    """
    messageEncrypted = cipher[256:]
    AESKey = getSessionKey(rsa, cipher)
    print()
    print("Server AES Key in binary")
    aeky = bin(int.from_bytes(AESKey, 'big', signed = False))
    print(aeky)
    print('__________')
    print(len(aeky))
    print("__________")

    
    aes = AESCipher(AESKey)
    return aes.decrypt(messageEncrypted)


def handle_client(sock, rsa):
    print('Waiting for a connection...')  # Wait for a conneciton
    connection, client_address = sock.accept()

    try:
        # Receive the data
        cipher = connection.recv(2048)
        print("Message Received...")

        message = myDecrypt(rsa, cipher)
        print("length of Decrypted message : {}".format(len(message)))
        
        if message:
            print("Received as: {}".format(message))
#            temp1 = int.from_bytes(message, 'big', signed = False))
            
            aes = AESCipher(getSessionKey(rsa, cipher))
            msg = aes.encrypt(message.upper())
            connection.sendall(msg)
        else:
            connection.sendall("Couldn't decrypt!")
    finally:
        # Clean up the connection
        connection.close()

    return True


# Main routine starts here

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port",
                    help='starting port where the server is listening on',
                    required=True)
parser.add_argument("-kp", "--publickey",
                    help='the public key for the server',
                    default='serverPublicKey',
                    required=False)
parser.add_argument("-ks", "--privatekey",
                    help='the private key for the server',
                    default='privateKey.pem',
                    required=False)

args = parser.parse_args()

port = int(args.port)
server_address = ('0.0.0.0', port)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind socket to port
try:
    sock.bind(server_address)
except OSError:
    print('Address {} already in use'.format(server_address))

# Listen for incoming connections
sock.listen(10)

pid = os.fork()

if pid == 0:
    rsa = RSACipher(publicKeyFileName=args.publickey,
                    privateKeyFileName=args.privatekey)

    while True:
        finished = handle_client(sock, rsa)
        if finished is True:
            print("Processed client message on port {}".format(port))
            sleep(1)
