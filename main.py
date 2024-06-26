import socket
import sys
from Server import handleClient
import os
def main():
    '''
    Purpose: the main function that runs the server-side of the secure mail 
             transfer protocol and its available functions
    Parameter: none
    Return: none
    '''

    # Create the server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print(">> Error in server socket creation: ", e)
        sys.exit(1)
    # end try and accept
        
    try:
        serverSocket.bind(("localhost", 13000))
    except socket.error as e:
        print(">> Error in server socket binding: ", e)
        sys.exit(1)
    # end try and accept

    # makes Server.py handle 5 connections in its queue waiting for acceptance
    serverSocket.listen(5)
    # sets a timout for accepting connection (value is in seconds)
    serverSocket.settimeout(10)
    

    # prints out a successful message the server has been initialized
    print(">> The server is ready to accept connections and is listening.")

    pid=os.fork()
    if pid>0:
        while True:
            clientUsingServerSocket, addr = serverSocket.accept()

            # accept a connection from a client

            # create a new thread to handle the client
            try:

                handleClient(clientUsingServerSocket, addr)
            except socket.timeout:
                print(">> No clients attempting to connect...")

                # ask the user in the server for an action
                serverAction = input(">> Do you want to continue waiting for connections? (Y/N): ").strip().lower()

                # exit the server loop if user chooses to stop waiting
                if (serverAction.lower() == 'n'):
                    print(">> Exiting server loop!")
                    break  
                # end if stateemnt
            except Exception as e:
                print(f">>Error creating thread: {e}")
                clientUsingServerSocket.close()
            # end try & accept
        # end while loop
        
        # closes the connection from the client
        clientUsingServerSocket.close()
        print(">> Closing the datalink. Thank you for using the program")
# end main()
    
if __name__ == "__main__":
    main()