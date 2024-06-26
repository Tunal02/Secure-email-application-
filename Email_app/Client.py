# ------------------------------------------------------------------------------
# Integrity Pledge:
# I declare that the work is being submitted is my own
# It was completed in accordance with MacEwan's Academic Integrity Policy
# Author(s): Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# ------------------------------------------------------------------------------
# Name of Group Members: Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# Program: Client.py
# ------------------------------------------------------------------------------
# Purpose: The program simulates a secure mail transfer protocol using client 
# and server programs in a UNIX-like environment.This program interfaces 
# seamlessly with the server, adhering to the specified protocol. Client.py must
# have implemented security measures to maintain the confidentiality and 
# integrity of transmitted data. The program also participates in identifying 
# and addressing potential vulnerabilities in the protocol, enhancing its 
# security posture.
# ------------------------------------------------------------------------------

# importing crucial libraries to simulate a secure mail transfer protocol
import os
import socket
import sys
from datetime import datetime as d
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import json

def loadServerPublicKey():
    '''
    Purpose: Load the server's public key from file server_public.pem
    Return: serverPublicKey - the loaded server's public key object
    '''
    try:
        with open("Server_keys/server_public.pem", "r") as file:
            serverPublicKey = RSA.import_key(file.read())
        return serverPublicKey
    except Exception as e:
        print(f"Error loading server's public key from file: {e}")
        return None
    # end try & accept
# end loadServerPublicKey()
    

def loadClientPublicKey(clientPublicKeyFile):
    '''
    Purpose: Load a private key from a file
    Parameter: clientPublicKeyFile - the file path of the private key
    Return: clientPublicKeyFile - the loaded private key object
    '''
    try:
        with open(clientPublicKeyFile, "r") as file:
            publicKey = RSA.import_key(file.read())
        return publicKey
    except Exception as e:
        print(f"Error loading public key from file {clientPublicKeyFile}: {e}")
        return None
    # end try & accept
# end loadClientPublicKey()
    

def loadClientPrivateKey(clientPrivateKeyFile):
    '''
    Purpose: Load a private key from a file
    Parameter: privateKeyFile - the file path of the private key
    Return: privateKey - the loaded private key object
    '''
    try:
        with open(clientPrivateKeyFile, "r") as file:
            privateKey = RSA.import_key(file.read())
        return privateKey
    except Exception as e:
        print(f"Error loading private key from file {clientPrivateKeyFile}: {e}")
        return None
    # end try & accept
# end lodClientPrivateKey()


def encrypt(data, publicKey):
    '''
    Purpose: Encrypt data using RSA public key
    Parameters: data - the data to be encrypted
                publicKey - the RSA public key object
    Return: encryptedData - the encrypted data
    '''
    try:
        cipher = PKCS1_OAEP.new(publicKey)
        encryptedData = cipher.encrypt(data.encode())
        return encryptedData
    except FileNotFoundError:
        print(f"Error: Public key not found.")
    except Exception as e:
        print(f">> Error encrypting data: {e}")
        return None
# end encryptSymKey()


def decrypt(encryptedSymmetricKey, clientPrivateKey):
    
    '''
    Purpose: Decrypt the encrypted symmetric key received from the server
    Parameter: encryptedSymmetricKey - The encrypted symmetric key
               clientPrivateKey - The client's private key
    Return: symmetricKey - The decrypted symmetric key
    '''
    # Create a cipher object for decryption
    cipher_rsa = PKCS1_OAEP.new(clientPrivateKey)

    # Decrypt the symmetric key
    symmetricKey = cipher_rsa.decrypt(encryptedSymmetricKey)

    return symmetricKey
# end decruptSymmetricKey()


def encryptWithSymKey(data, sym_key,iv):
    '''
    Purpose: Encrypt data using AES symmetric key
    Parameters: data - the data to be encrypted
                sym_key - the symmetric key
    Return: encryptedData - the encrypted data
    '''
    try:
        cipher = AES.new(sym_key, AES.MODE_CBC,iv)
        data=str(data)
        data = data.encode()
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data   
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None
# end encrypt()
      

def decrpyt_sym(data, sym_key,iv):
    cipher = AES.new(sym_key, AES.MODE_CBC,iv)
    decrypted_data = cipher.decrypt(data)
    ubpadd=unpad(decrypted_data, AES.block_size)
    return ubpadd.decode('utf-8')
    

# end decrypt()


def sendEmail(clientSocket, sym_key):
    iv=clientSocket.recv(16)
    mssg = clientSocket.recv(1024)
    mssg = decrpyt_sym(mssg, sym_key,iv)
    sender_username = input("Enter your username: ")
    destination_usernames = input("Enter destination usernames separated by ';': ")
    destination_usernames= destination_usernames.split(',')    
    email_title = input("Enter email title: ")
    message_contents = input("Enter message contents: ")
    content_length = len(message_contents)
    email_message = {
        "sender": sender_username,
        "destinations": destination_usernames,
        "title": email_title,
        "content_length": content_length,
        "message_contents": message_contents
    }

    # Encrypt email message
    iv=get_random_bytes(16)
    encrypted_email = encryptWithSymKey(json.dumps(email_message), sym_key,iv)
    clientSocket.send(iv)
    clientSocket.send(encrypted_email)
    print("The message is sent to the server.")
# end sendEmail()
    

def viewEmail(clientSocket, sym_key):
    iv=clientSocket.recv(16)
    mssg = clientSocket.recv(1024)
    mssg = decrpyt_sym(mssg, sym_key,iv)
    print(mssg)

    client_username = input("Enter your username: ")
    validIndex = False

    while not validIndex:
        email_index = input("Enter the email index you wish to view: ")

        try:
            email_index = int(email_index)
            validIndex = True
        except:
            continue
    
    email_rerquest = {
        "sender": client_username,
        "emailIndex": email_index
    }
    
    # Encrypt email message and send it
    iv=get_random_bytes(16)
    encrypted_email = encryptWithSymKey(json.dumps(email_rerquest), sym_key,iv)
    clientSocket.send(iv)
    clientSocket.send(encrypted_email)

    # recieve and decrypt the clients message then process req
    iv=clientSocket.recv(16)
    encrypted_email_new=clientSocket.recv(4096)
    d_email=decrpyt_sym(encrypted_email_new,sym_key,iv)
    d_email = d_email.replace("\'", "\"")

    try:
        email_object=json.loads(d_email)
        sender=email_object["sender"]
        destination=email_object["destinations"]
        title=email_object["title"]
        length=email_object["content_length"]
        contents=email_object["message_contents"]
        
        print(f"An email from {sender} is sent to {destination} ")
        print(f"with a content length of {length} characters.")
        print(f"Title: {title}")
        print(f"Content Length: {length}")
        print(f"Content:\n{contents}")
        
    except:
        print(f">>Email doesn't exist")
   

    
    # TODO: display email
# end viewEmail()
    

def displayInbox(clientSocket, sym_key):
    '''
    Purpose: Receive and display inbox emails' information from the server
    Parameter: clientSocket - socket object for client communication
               sym_key - symmetric key for decryption
    Return: none
    '''
    try:
        # Receive and decrypt inbox email information from the server
        iv=clientSocket.recv(16)
        info = clientSocket.recv(1024)
        inbox_info = decrpyt_sym(info, sym_key,iv)
        # Convert the decrypted JSON string back to a Python list of dictionaries
        inbox_emails = json.loads(inbox_info)

        # Display inbox email information
        if inbox_emails:
            print("Inbox emails:")
            for email in inbox_emails:
                print(f"Index: {email['index']}, Sender: {email['sending_client']}, Date/Time: {email['date_time']}, Title: {email['title']}")
            mssg="OK"
            my_bytes = mssg.encode('utf-8')
            clientSocket.send(my_bytes)

        else:
            print("Inbox is empty.")
            clientSocket.send("Not ok".encode('utf-8'))

    except Exception as e:
        print("Error:", e)
# end displayInbox()


def authenticateWithServer():
    '''
    Purpose: a helper function that tries to connect and authenticate the user
             to the sercure Email server
    Parameter: none
    Return: clientSocket - the vital connection to the server
            symetra - the key that can decrypt encrypted messages from the server
    '''
    # create a client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print(">> Error in client socket creation: ",e)
        sys.exit(1)    
    # end try & except

    try:
        # client tries to connect with the server
        clientSocket.connect(("localhost", 13000))
    except socket.error as e:
        print(">> An error occured in the client-side:'", e)
        clientSocket.close()
        sys.exit(1)
    # end try & except()

    # asks the user for the IP address
    userServerIP = input(">> Enter the server's IP address: ")
    clientSocket.send(userServerIP.encode())

    # If the IP address entered is incorrect
    userClientIP = clientSocket.recv(1024).decode()
    if (userClientIP == ">> Wrong IP Address"):
        print(">> Wrong IP Address. Closing connection.")
        clientSocket.close()
        sys.exit(1)
    else:
        print(userClientIP)
    # end if statement
    print("\n>>Welcome to the Email app\n")
    
    # get username and password from user input
    username = input("\n>> Enter your username: ")
    password = input(">> Enter your password: ")
    
    # Load server's public key
    serverPubKey = loadServerPublicKey()

    # Encrypt username and password
    encryptedUsername = encrypt(username, serverPubKey)
    encryptedPassword = encrypt(password, serverPubKey)

    # Send encrypted username and password to server
    clientSocket.send(encryptedUsername)
    clientSocket.send(encryptedPassword)

    # receiving data from Server.py for a welcome message
    authenticationMSG = clientSocket.recv(1024).decode()
    if (authenticationMSG == ">> Authentication failed!"):
        print(">> Authentication has failed! Closing connection.")
        clientSocket.close()
        sys.exit(1)
    # end if statement
        
    # receive symmetric key from server and decrypt it to 'symetra'
    encryptedSymetra = clientSocket.recv(1024)
    clientPrivateKeyFile = f"client_keys/{username}/{username}_private.pem"
    clientPrivateKey = loadClientPrivateKey(clientPrivateKeyFile)

    clientPublicKeyFile = f"client_keys/{username}/{username}_public.pem"
    clientPubKey=loadClientPublicKey(clientPublicKeyFile)

    sym_key = decrypt(encryptedSymetra, clientPrivateKey)
    if sym_key:
        print("sym_key Recieved ")
    #encryptedMessage = encrypt('OK', sym_key)
    #clientSocket.send(encryptedMessage)
    
    return clientSocket, clientPrivateKey,clientPubKey,sym_key
# end authenticateWithServer()


def main():
    '''
    Purpose: the main function that runs the server-side of the secure mail 
             transfer protocol and its available functions
    Parameter: none
    Return: none
    '''
    os.chdir("..") 
    # call a helper function to authenticate to the server
    clientSocket, clientPrivateKey,clientPubKey,sym_key = authenticateWithServer()
    # receiving data from Server.py for a welcome message
    

    while True:
        serverMessage = clientSocket.recv(1024).decode('utf-8')
        print(serverMessage)
        userChoice = input('Enter Choice')
        clientSocket.send(userChoice.encode())
        # receive the  server's menu options
        
        # gets, encrypts and sends the user's choice to the server
        #encryptedChoice = encrypt(userChoice, clientPrivateKey)
        #clientSocket.send(userChoice)
        
        if(userChoice=='1'):
            sendEmail(clientSocket,sym_key)
        
        elif(userChoice=='2'):
            displayInbox(clientSocket, sym_key)
        elif(userChoice == '3'):

            viewEmail(clientSocket,sym_key)
        # terminate the connection if the user chooses so
        elif (userChoice == '4'):
            clientSocket.sendall("Ending".encode('utf-8'))
            break
        # end if statement
    # end while loop
    
        # closes the connection to the server
        else:
            clientSocket.close()
    
    # end try & accept
# end main()
        
if __name__ == "__main__":
    main()
# end if statement