# ------------------------------------------------------------------------------
# Integrity Pledge:
# I declare that the work is being submitted is my own
# It was completed in accordance with MacEwan's Academic Integrity Policy
# Author(s): Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# ------------------------------------------------------------------------------
# Name of Group Members: Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# Program: Server.py
# ------------------------------------------------------------------------------
# Purpose: The program simulates Develop a secure mail transfer protocol 
#          implemented through server and client programs in a UNIX-like 
#          environment. This program can handle multiple clients concurrently 
#          using the fork function to create multiple processes. The program
#          also implemented security measures to reasonably secure the mail 
#          transfer application. Also, Server.py identifies potential attacks 
#          against the developed protocol and enhance it to defend against these
#          attacks.
# ------------------------------------------------------------------------------
# importing crucial libraries to simulate a secure mail transfer protocol
import hashlib
import json
import os
import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from datetime import datetime as d


def generateSymmetricKey():
    '''
    Purpose: Generate a symmetric key for encryption using AES with a key length of 256 bits.
    Parameter: None
    Return: symKey - The generated symmetric key
    '''
    # Generate a random symmetric key using AES with a key length of 256 bits
    symKey = get_random_bytes(32)  # 256 bits key length
    return symKey
# end generateSymmetricKey()
    
def encryptMessage(message, publicKey):
    '''
    Purpose: a helper function that uses asymmetric encryption to secure the
             message. It uses the client's public key to encrypt the message
    Parameter: message - a bytes-like object that holds the data to be encrypted
               publicKey - the public key object (RSA key) to be used for encryption
    Return: encryptedData - the encrypted message
    '''
    try:
        # Check if the message and public key are not None
        if message is None or publicKey is None:
            print(">> Error: Neither the message nor the public key is present.")
            return None
        with open("server_private.pem", "r") as file:
            privateKey = RSA.import_key(file.read())
        # Create a cipher object with the public key
        cipher = PKCS1_OAEP.new(publicKey)
        # Encrypt the message and return the encrypted data
        encryptedData = cipher.encrypt(message)

        return encryptedData

    except Exception as e:
        print("Error encrypting message:", e)
        return None

def decrpyt_sym(data,sym_key,iv):
    cipher = AES.new(sym_key, AES.MODE_CBC,iv)
    decrypted_data = cipher.decrypt(data)
    unpadd=unpad(decrypted_data, AES.block_size)
    print(unpadd)
    return unpadd.decode('utf-8')
   

def decipherMessage(encryptedMSG):
    '''
    Purpose: a helper function that uses the server's private key to decipher
             the message
    Parameter: encryptedMSG - a string that holds the encrypted text data
    Return: decipheredMSG - a deciphered message from client
    '''
    try:
        # load the server's private key
        with open("server_private.pem", "r") as file:
            privateKey = RSA.import_key(file.read())
        # end with
            
        # create cipher object with private key
        cipher = PKCS1_OAEP.new(privateKey)
        # decrypt the message
        decipheredMSG = cipher.decrypt(encryptedMSG)

        # returns the deciphered message
        return decipheredMSG.decode()
    except FileNotFoundError:
        print(f">> Error: Private key not found.")
    except Exception as e:
        print(f">> Error decrypting client message: {e}")
        return None
    # end try & accept
# end decipherMessage()


def loadUserInfo():
    '''
    Purpose: a helper function that reads the .json file that holds all known
             users and their passwords
    Parameter: none
    Return: userInfo - a string list of users and their passwords
    '''
    try:
        with open("user_pass.json", "r") as f:
            userInfo = json.load(f)
        # end with
    except FileNotFoundError:
        print(f">> Key files for user information has not been found!")
        print(f">> Initializing known clients...")
        # calls a helper function to initalize a list of clients
        userInfo = startKnownClients()
        # calls a helper function to save it to the .json file
        saveUserInfo(userInfo)
    # end try & accept
        
    return userInfo
# end loadUserInfo()
 

def saveUserInfo(knownClients):
    '''
    Purpose: a helper function that saves the known Clients back to .json file
    Parameter: knownClients - a data structure that holds all known authorized
                              clients
    Return: none
    '''
    try:
        # Save user info to JSON file
        with open("user_pass.json", "w") as file:
            json.dump(knownClients, file, indent = 4)
        print(">> User info saved to 'user_pass.json'")
    except Exception as e:
        print(">> Error:", e)
    # end try & accept
# end saveUserInfo()
        

def startKnownClients():
    '''
    Purpose: a helper function that initializes a dictionary with known
             authorized users for clients
    Parameter: none
    Return: knownClients - the dictionary with known clients
    '''
    # initiallizes a dictionary with all 5 authorized clients
    knownClients = {
        "John": "badboat68",
        "David": "(oolheat19",
        "Lucy": "b!gBox99",
        "Dorio": "calmKoala41",
        "Bob": "123456"
    }

    return knownClients
# end startknownCLients()


def authenticateUser(username, password):
    '''
    Purpose: a helper function that checks if the user is in the file for
             authorized users along with their password
    Parameter: username - a string that holds the username
               password - a string that holds the password
    Return: a boolean that indicates if the user is authorized or not
    '''
    # calls helper function to get information
    userPass = loadUserInfo()
    # checks and returns a boolean value
    return username in userPass and userPass[username] == password
# end authenticateUser()


def loadClientPublicKey():
    '''
    Purpose: Load a private key from a file
    Parameter: none
    Return: clientPublicKeys - a dictionary that holds the the public keys of
                               all known users
    '''
    # initialize a dictionary to hold the information
    clientPublicKeys = {}
    # saves information of known clients and their passwords
    users = loadUserInfo()

    # loops until every client is analyzed
    for username in users:
        # concatenates the user's name to the filepath
        publicKeyPath = f"client_keys/{username}/{username}_public.pem"

        if os.path.exists(publicKeyPath):
            try:
                with open(publicKeyPath, 'r') as f:
                    clientPublicKeys[username] = RSA.import_key(f.read())
                # end with
            except (FileNotFoundError, ValueError) as e:
                print(f">> Error loading public key for user '{username}': {e}")
            # end try & accept
        else:
            print(f"\t>> Public key file not found for user '{username}'.")
        # end if statement
    return clientPublicKeys
# end loadClientPublicKey()


def loadServerKeys():
    '''
    Purpose: a helper function that loads the public and private keys for the
             Server. The Keys must be a matching pair
    Parameter: username - a string that holds the username given
    Return: serverPublicKey - the public key of the server
    '''
    try:
        # attempting to load both the server's public and private keys
        with open("server_private.pem", 'r') as file:
            privateKey = RSA.import_key(file.read())
        # end with
        with open("server_public.pem", 'r') as file:
            publicKey = RSA.import_key(file.read())
        # end with
    except FileNotFoundError:
        print(">> Server's keys are not found. Generating server's keys...")
        
        # generate a new key if the loaded key is invalid
        serverKey = RSA.generate(2048)
        # extract the keys as bytes
        publicKey = serverKey.publickey().export_key()
        privateKey = serverKey.export_key()

        # calls a helper function to save the generatedServerPublicKey
        saveServerKeys(publicKey, privateKey)
        print(">> New server key-pair generated and saved.")
    except ValueError as e:
        print(f">> Error loading server key pair: {e}")
        print(">> Server's keys are not found. Generating server's keys...")

        # generate a new key if the loaded key is invalid
        serverKey = RSA.generate(2048)
        publicKey = serverKey.publickey().export_key()
        privateKey = serverKey.export_key()
        
        # save the generated keys
        saveServerKeys(publicKey, privateKey)
        print(">> New server public key generated and saved.")
    # end try & accept
        
    return publicKey, privateKey
# end loadServerPublicKey()


def saveServerKeys(publicKey, privateKey):
    '''
    Purpose: a helper function that saves the generated server public key
    Parameter: publicKey - a string that is the server public key
               privateKey - a string that is the server private key
    Return: none
    '''
    try:
        # saves the server's public key to .pem file
        with open("server_public.pem", 'wb') as file:
            file.write(publicKey)
        # end with
        print("\t>> Server's public key saved as 'server_public.pem'")

        # saves the server's private key to .pem file
        with open("server_private.pem", 'wb') as file:
            file.write(privateKey)
        # end with
        print("\t>> Server's private key saved as 'server_private.pem'")
    except Exception as e:
        print(">> Error in saving Server keys:", e)
    # end try & accept
# end saveServerPublicKey()
        

def startCreatingUserKeys():
    '''
    Purpose: a helper function that creates a public and private key for all 5
             known users. This function is similar to startKnownClients()
    Parameter: none
    Return: none
    '''
    # define the names of the known users
    knownUsers = ["John", "David", "Lucy", "Dorio", "Bob"]

    # loops until the known users are done
    for username in knownUsers:
        # generate a key pair for the user
        keyPair = RSA.generate(2048)
        publicKey = keyPair.publickey().export_key()
        privateKey = keyPair.export_key()

        # save the public key to a .pem file
        publicKeyFilename = f"client_keys/{username}/{username}_public.pem"
        with open(publicKeyFilename, 'wb') as f:
            f.write(publicKey)
        # end with
            
        # save the private key to a .pem file
        privateKeyFilename = f"client_keys/{username}/{username}_private.pem"
        with open(privateKeyFilename, 'wb') as f:
            f.write(privateKey)
        # end with
            
        print(f"\t>>Key pair generated for user '{username}'")
    # end for loop
        
    print(">> Public and private keys saved as .pem files.")
# end startCreatingUserKeys()


def checkPemFilesExist():
    '''
    Purpose: Check if .pem files exist for each user
    Parameter: None
    Return: True if .pem files exist for all users, False otherwise
    '''
    # define the names of the known users
    knownUsers = ["John", "David", "Lucy", "Dorio", "Bob"]

    # loops and checks if .pem files exist for each user
    for username in knownUsers:
        public_key_filename = f"client_keys/{username}/{username}_public.pem"
        private_key_filename = f"client_keys/{username}/{username}_private.pem"

        # check if both public and private key files exist for the user
        if not (os.path.exists(public_key_filename) and os.path.exists(private_key_filename)):
            return False
        # end if statement
    # end for loop
    return True
# end checkpemFilesExist()
def encryptWithSymKey(data, sym_key,iv):
    '''
    Purpose: Encrypt data using AES symmetric key
    Parameters: data - the data to be encrypted
                sym_key - the symmetric key
    Return: encryptedData - the encrypted data
    '''

    try:
        
        # Generate a random initialization vector (IV)
        cipher = AES.new(sym_key, AES.MODE_CBC,iv)
        data=str(data)
        data = data.encode('utf-8')        
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data   
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None

def createEmail(clientSocket,sym_key):

    '''
    Purpose: a helper function that lets the user create and send an email to
             the server
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
    iv=get_random_bytes(16)
    encrypted_message=encryptWithSymKey("send the email",sym_key,iv)
    clientSocket.sendall(iv)
    clientSocket.sendall(encrypted_message)
    
    iv=clientSocket.recv(16)
    encrypted_email=clientSocket.recv(4096)
    decrypted_email=decrpyt_sym(encrypted_email,sym_key,iv)
    processEmail(decrypted_email)
   
    clientSocket.sendall(b"Email received by the server.")
# end createEmail()
    

def processEmail(email_object):
    '''
    Parameter: The email json object that's sent from the client side
    purpose: Extract email info, print it to server side, and save the emails to text file 
    return :none
    '''
    destin=""
    email_object=json.loads(email_object)

    #extract email info
    sender=email_object["sender"]
    destination=email_object["destinations"]
    title=email_object["title"]
    length=email_object["content_length"]
    contents=email_object["message_contents"]
    # The time and date of receiving the message, add  it to the email object
    timestamp = d.now().strftime("%Y-%m-%d %H:%M:%S")
    for destinations in destination:
        destin+=f"{destinations} "
    # end for loop

    #print the details of the email 
    print(f"An email from {sender} is sent to {destin} ")
    print(f"with a content length of {length} characters.")
    print(f"Title: {title}")
    print(f"Content Length: {length}")
    print(f"Content:\n{contents}")
    email_object["Time"]=timestamp
    #added time stamp to the new email object

    for new_des in destination:
        saveEmail(sender,new_des,title,email_object)
        # For each destination send email
    # end for loop
# end processEmail()
        

def saveEmail(sender,destination,title,email_object):
    os.makedirs('client_emails',exist_ok=True)
    client_folder_path=os.path.join('client_emails',destination)
    #client_folder=os.path.join(folder,destin_dir)
    # create a new folder, that contains the users
    os.makedirs(client_folder_path, exist_ok=True)
    
    filename=f"{sender}_{title}.txt"
    # creates a file  that tracks for each user email
    added_file=os.path.join(client_folder_path,filename)
    with open(added_file,'w') as file:
        # write json object to newly created file
        json.dump(email_object,file)
    
    # end with()
        
    print(f"Email has been sent successfully to {destination}\n")
# end saveEmail()


def displayEmail(clientSocket, symkey):
    '''
    Purpose: a helper function that displays any email's content in the server's
             inbox
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
    # send the client a message
    iv=get_random_bytes(16)
    encrypted_message = encryptWithSymKey("the server request email index",symkey,iv)
    print(encrypted_message)
    clientSocket.send(iv)

    clientSocket.send(encrypted_message)
    # recieve and decrypt the clients message then process req
    iv=clientSocket.recv(16)
    encrypted_email = clientSocket.recv(4096)
    decrypted_email = decrpyt_sym(encrypted_email,symkey,iv)
    
    email_view = getEmail(decrypted_email)
    iv=get_random_bytes(16)
    encrypted_email_view= encryptWithSymKey(email_view, symkey,iv)

    clientSocket.send(iv)
    clientSocket.send(encrypted_email_view)
# end displayEmail()


def getEmail(emailReq):
    """
    Purpose: Process the email request then send the client the email, assumers
             correct emailReq contains valid information.
    Parameter: emailReq
    Return: emailDate
    """
    try:
        emailReq = json.loads(emailReq)
        clientBox = emailReq["sender"]
        emailIndex = emailReq["emailIndex"]

        # Directory where client's emails are stored
        destinDIR = os.path.join("client_emails", clientBox)
        
        # List all .txt files in the user's directory
        emailFiles = [file for file in os.listdir(destinDIR) if file.endswith('.txt')]
        
        # Select the email file based on the emailIndex
        selectedMail = emailFiles[emailIndex - 1]  # correct index for file
        emailPath = os.path.join(destinDIR, selectedMail)
        
        # Read the email data from the selected file
        with open(emailPath, 'r') as emailFile:
            emailData = json.load(emailFile)
            print(emailData)
        
        return emailData
    
    except Exception as e:
        print(f"Error retrieving email: {e}")
        return None


    # end with
# end getEmail()


def displayInbox(clientSocket, sym_key, client_username):
    '''
    Purpose: Send the client inbox emails' information sorted by received time and date
    Parameter: clientSocket - socket object for client communication
               sym_key - symmetric key for encryption
               client_username - username of the requesting client
    Return: none
    '''
    try:
        # Path to the directory containing inbox emails for the requesting client
        client_inbox_dir = os.path.join("client_emails", client_username)
        print(client_inbox_dir)
        # Check if the client's inbox directory exists
        if not os.path.exists(client_inbox_dir):
            # If the directory does not exist, send an empty inbox email list
            inbox_emails = []
        else:
            # List all .txt files in the client's inbox directory
            email_files = [file for file in os.listdir(client_inbox_dir) if file.endswith('.txt')]

            # Initialize an empty list to store inbox email information
            inbox_emails = []
            index=0
            # Iterate over each email file and extract relevant information
            for email_file in email_files:
                with open(os.path.join(client_inbox_dir, email_file), 'r') as email:
                    email_data = json.load(email)
                    print(email_data)
                    index+=1
                    inbox_emails.append({
                        "index": index,
                        "sending_client": email_data["sender"],
                        "date_time": email_data["Time"],
                        "title": email_data["title"]
                    })

        # Sort inbox emails by received time and date
        inbox_emails = sorted(inbox_emails, key=lambda x: x["date_time"])

        # Prepare the message containing inbox email information
        message = json.dumps(inbox_emails)
        # Encrypt the message using AES symmetric encryption with the provided symmetric key
        iv=get_random_bytes(16)
        new=encryptWithSymKey(message,sym_key,iv)
        # Send the encrypted message to the client
        clientSocket.send(iv)
        clientSocket.send(new)

        # Receive acknowledgment from the client
        acknowledgment = clientSocket.recv(1024).decode()
        if (acknowledgment == "OK"):
            print(f"Inbox emails sent to {client_username}.")
        else:
            print("Error: Client acknowledgment not received or invalid.")
        # end if statement
    except Exception as e:
        print("Error:", e)
    # end try & accept
# end displayInbox()  


def handleClient(clientUsingServerSocket, addr):
    '''
    Purpose: Handles each client connection individually while calling helper
             functions
    Parameter: clientUsingServerSocket - socket object for client communication
               addr - client address
    Return: none
    '''

    # gets the IP address of the client's machine
    hostname = socket.gethostname()
    address = socket.gethostbyname(hostname)
    # receives information from client about the IP
    userIP = clientUsingServerSocket.recv(1024).decode()

    # checks if the user correctly typed the correct local IP address 
    if (userIP == address) or (userIP == "localhost"):
        print(f">> Connection established with {addr}")
        clientUsingServerSocket.send(">> Connection established!".encode())
    else:
        clientUsingServerSocket.send(">> Wrong IP Address".encode())
        clientUsingServerSocket.close()
    # end if statement
    
    # check if .pem files for the keys of the known users exist
    if not checkPemFilesExist():
        # If .pem files do not exist for all users, create them
        startCreatingUserKeys()
    else:
        print(">> Public and private key files already exist for all users.")
    # end if statement
        
    # load server's public key and private key
    serverPubKey, serverPrivKey = loadServerKeys()
    # load client's keys; clientPubKeys is a dictionary
    clientPubKeys = loadClientPublicKey()

    # receives username and password from Client.py
    username = clientUsingServerSocket.recv(1024)
    password = clientUsingServerSocket.recv(1024)

    # decodes the username and password with 'server_public' key
    username = decipherMessage(username)
    password = decipherMessage(password)

    # loading all known users and their passwords [DICTIONARY]
    userINFO = loadUserInfo()

        
    # checks if the user is authenticated by calling a helper function
    if (username in userINFO and userINFO[username] == password):
        clientUsingServerSocket.send(">> Authenticated".encode())
        print(f"\n>> User {username} authenticated!")

        # Generate a symmetric key for the client
        symKey = generateSymmetricKey()
        
        # Send the symmetric key encrypted with the client's public key
        encryptedSymKey = encryptMessage(symKey, clientPubKeys[username])
        clientUsingServerSocket.send(encryptedSymKey)
        print(">> The server sent the encrypted symmetrical key")

        # Print a message indicating the connection is accepted and a symmetric key is generated for the client
        print(f">> Connection Accepted and Symmetric Key Generated for client: {username}")

       
       
    else:
        clientUsingServerSocket.send(">> Authentication failed!".encode())
        print(f"\t>> Authentication failed for {username}. Connection closed.")
    # end if statement
        
    # sending welcome message and receiving user's credentials
    serverWelcomeMessage = ">>> Welcome to the Email Server <<<\n"
    clientUsingServerSocket.send(serverWelcomeMessage.encode())
    menu = ">> Select an operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n>> User's choice: "

            #encryptedMenu = encryptMessage(menu.encode(), clientPubKeys[username])
    

    while True:

        #try:
        clientUsingServerSocket.send(menu.encode('utf-8'))
            # receives an encrypted choice from the client
    # main communication loop to handle the client
        choice = clientUsingServerSocket.recv(1024).decode()
            # a string that holds the menu

        if (choice == '1'):
            # Handle sending email
            createEmail(clientUsingServerSocket,symKey)
            
        elif (choice == '2'):
            # Handle displaying inbox list
            displayInbox(clientUsingServerSocket, symKey, username)
        elif (choice == '3'):
            # Handle displaying email contents
            displayEmail(clientUsingServerSocket,symKey)
            print(" ")
        elif (choice == '4'):
            msg=clientUsingServerSocket.recv(1024)
            print(msg)
            
            # Terminate connection
        #except Exception as e:
        # end try & accept
    # end major while loop
# end handleClient()


