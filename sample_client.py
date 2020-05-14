import argparse
import os
import time
import socket
import sys
from aes import AESCipher
from Crypto.PublicKey import RSA

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress",
                    help='ip address where the server is running',
                    default='127.0.0.1',  # Defaults to loopback
                    required=True)
parser.add_argument("-p", "--port",
                    help='port where the server is listening on',
                    required=True)
parser.add_argument("-f", "--publickey",
                    help='name of public key',
                    default='serverPublicKey',
                    required=False)
parser.add_argument("-v", "--verbose",
                    help="print out extra info to stdout",
                    default='True',
                    required=False)

args = parser.parse_args()

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (args.ipaddress, int(args.port))
sock.connect(server_address)
sock.settimeout(2)

AESKey = os.urandom(32)
while AESKey[0] == 0:  # Make sure there aren't leading 0s
    AESKey = os.urandom(32)

if args.verbose is True:
    binKey = bin(int.from_bytes(AESKey, byteorder='big'))
    print("Using AES key : {}".format(binKey))

# load server's public key
serverPublicKeyFileName = args.publickey
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

MESSAGE_LENGTH = 2048

encryptedKey = key.encrypt(AESKey, 32)[0]
aes = AESCipher(AESKey)
print("total len of raw aes : {}".format(len(AESKey)))
print('______________')

try:
    # Send data
    try:
#        message = aes.encrypt('This is my own test message to attack')
        message = aes.encrypt('Test')
    except ValueError:
        print("Client with port {} failed.".format(args.port),
              file=sys.stderr)
        exit(1)
    msg = encryptedKey + message
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key

    print("total len of msg sent : {}".format(len(msg)))
    print('______________')
    print("total len of cipher text : {}".format(len(encryptedKey)))
    print("_______________")

    
    if args.verbose is True:
        print('Sending: {}'.format(message.hex()))
    sock.sendall(msg)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))

    answer = b''
    if amount_expected > amount_received:
        while amount_received < amount_expected:
            try:
                data = sock.recv(MESSAGE_LENGTH)
            except socket.timeout as e:
                err = e.args[0]

                if err == 'timed out':
                    print('Connection timed out, waiting for retry',
                          file=sys.stderr)
                    time.sleep(1)
                    continue
                else:
                    print('Another issue: {}'.format(e),
                          file=sys.stderr)
                    break
            except socket.error as e:
                print('Socket error: {}'.format(e),
                      file=sys.stderr)
                break
            amount_received += len(data)
            answer += data

            print("length of data received : {} ".format(amount_received))
            print("_____________")
            print("Answer without decrypting : {} ".format(answer))
            print("_____________")
            
    print('Received: {}'.format(aes.decrypt(answer)))

finally:
    sock.close()
