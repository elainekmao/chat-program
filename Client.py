#Elaine Mao
#ekm2133
#Computer Networks

#Programming Assignment 1 - Client

import sys, os
import socket
from threading import *

#Main code for program
def main (address, port):
    HOST = address
    PORT = int(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT)) #While loop goes here?
    def recv():                             #Listens for incoming messages from server
        while True:
            data = s.recv(1024)
            if not data:
                sys.exit(0)
            print data
            if data == 'You have been logged out due to inactivity.':
                break
            while True:
                command = raw_input('')
                s.sendall(command)
                reply = s.recv(1024)
                print reply
            break
        s.close()
        os._exit(1)
    Thread(target=recv).start()             #Creates new thread to run recv
    username = ''                           #Sets variables for authentication loop
    while True:
        while True:                         #Authentication loop 
            while not username:
                username, password = authenticate()
                s.sendall('login ' + username + ' ' + password)
                reply = s.recv(1024)
                if reply == 'Your username/password combination is incorrect.':
                    print reply + '\n'
                    username = ''
                elif reply == 'Sorry, that user is already logged in.':
                    print reply + '\n'
                    username = ''
                elif reply == 'You have been blocked for too many incorrect tries.':
                    print reply + '\n'
                    username = ''
                else:
                    print reply
                    break
            break
        while True:
            command = raw_input('')
            s.sendall(command)
            reply = s.recv(1024)
            print reply
            if reply == 'You have been logged out.':
                break
        break
    s.close()
    sys.exit(0)

#Code to authenticate user
def authenticate ():
    username = ''
    password = ''
    while not username:
        username = raw_input('Username: ')
    while not password:
        password = raw_input('Password: ')
        return username, password

if __name__ == "__main__": main(sys.argv[1], sys.argv[2])