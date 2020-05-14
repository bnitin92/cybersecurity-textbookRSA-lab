import argparse
import os
import time
import socket
import sys
from aes import AESCipher
from Crypto.PublicKey import RSA

t_start = time.perf_counter()
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



if args.verbose is True:
    binKey = bin(int.from_bytes(AESKey, byteorder='big'))
    print("Using AES key : {}".format(binKey))


# load server's public key
serverPublicKeyFileName = args.publickey
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

MESSAGE_LENGTH = 2048


# getting encrypted AESkey data bytes of original message pcap
    
with open("mylab_pcap_bytes","rb") as files:
    file_bytes = files.read()

byte_ci = file_bytes[:256]
int_ci = int.from_bytes(byte_ci, 'big', signed = False)
#new_ci = ((pow(2, abs(255 * key.e), key.n)) * int_ci ) % key.n  

i = 255
bit = '1'
suffix_bits = ''

while i >= 0:

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.ipaddress, int(args.port))
    sock.connect(server_address)
    sock.settimeout(2)

    # creating AESKeys 
    AESKey_bit =  bit + suffix_bits
    for _ in range(i):
        AESKey_bit += '0'
        
    # converting to int    
    AESKey_int = int(AESKey_bit,2)

    # converting to bytes
    AESKey = AESKey_int.to_bytes(32,byteorder='big', signed=False)

    
    aes = AESCipher(AESKey)
    
    # Encrypting message using aes
    try:
        message = aes.encrypt('Test')
    except ValueError:
        print("Client with port {} failed.".format(args.port),
              file=sys.stderr)
        exit(1)


    p = i * key.e
    new_ci = ((2 ** (p % key.n)) * int_ci) % key.n
    print(len(bin(new_ci)))
    c_i = new_ci.to_bytes(256, 'big', signed=False)

    # Sending data

    msg = c_i + message
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key


    if args.verbose is True:
        print('Sending: {}'.format(message.hex()))

    #time.sleep(2)
    sock.sendall(msg)
    print('msg sent for {} {} {}'.format(i,bit, suffix_bits))

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))
    print('___________')
    print('amout expected {}'.format(amount_expected))
    answer = b''
    if amount_expected > amount_received:
        while amount_received < amount_expected:
            try:
                data = sock.recv(MESSAGE_LENGTH)
                print("daata_sock_recv")
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
            print(amount_received)
            if amount_received == 0:
                sock.close()
            answer += data


    decrypted_answer = aes.decrypt(answer)[:4]
    print('Received: {}'.format(decrypted_answer))
    
    correct_answer = b'TEST' == decrypted_answer

    print(correct_answer)

    sock.close()

    if correct_answer:
        i -= 1
        suffix_bits = bit + suffix_bits
        print('Correct')
    else:
        bit = str(1-int(bit))
        print('Incorrect choosen')
        

#sock.close()
print("finished : {}".format(suffix_bits))
with open("mylab_pcap_bytes","rb") as files:
    file_bytes_m = files.read()

byte_message = file_bytes_m[256:]
#int_ci = int.from_bytes(byte_ci, 'big', signed = False)                  
print("_____________")

AESKey_bits = suffix_bits
print("Final AESKey in bits : {} ".format(AESKey_bits))
AESKey = int(AESKey_bits, 2).to_bytes(32, 'big', signed=False)

aes = AESCipher(AESKey)
print('_____________')
print('Decrypted message back: {}'.format(aes.decrypt(byte_message)))
t_stop = time.perf_counter()
t = (t_stop - t_start) / 60
print("Total time taken = {}".format(t))
