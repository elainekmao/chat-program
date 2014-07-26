#Elaine Mao
#ekm2133
#Computer Networks

#Programming Assignment 1 - Server

import sys, string, time, collections
import socket
from thread import *

#Variables that can be changed, time should be expressed in seconds
BLOCK_TIME = 60     #1 minute
LAST_HOUR = 3600    #60 minutes
TIME_OUT = 1800     #30 minutes

#Loads in file with usernames and passwords
logindic = {}
loginfile = open('user_pass.txt', 'rb')
for line in loginfile:
    row = line.split()
    logindic[row[0]] = row[1]

#Creates Server class and methods
class ChatServer:
    def __init__(self):
        self.loggedin = {}                                  #Keeps track of usernames logged in and their associated connection
        self.loggedinbyconn = {}                            #Keeps track of connections and the username they are logged in under
        self.loginblocked = collections.defaultdict(list)   #Keeps track of which addresses and usernames are blocked
        self.blocked = collections.defaultdict(list)        #Keeps track of which users are being blocked by which other users
        self.loggedout = {}                                 #Keeps track of the logout time of each user
        self.storedmessages = collections.defaultdict(list) #Stores offline messages
        self.lastactive= {}                                 #Keeps track of when each user was last active
        self.loginattempts = collections.defaultdict(int)
    def whoelse(self, conn):                                #Implements whoelse function
        user = self.loggedinbyconn[conn]                    #Gets username of requesting user
        return filter(lambda x: x != user, self.loggedin.keys())    #Returns list of all other logged in users
    def wholasthr(self, conn):                              #Implements wholasthr function
        user = self.loggedinbyconn[conn]                
        now = time.time()                                   #Gets current time of request
        reply = []
        for username in self.loggedout:                     #Checks when users logged out
            if now - self.loggedout[username] < LAST_HOUR:  #If it was less than LAST_HOUR, appends username to reply
                reply.append(username)
        return filter(lambda x: x != user, reply)
    def block(self, conn, recipient):                       #Implements blocking of private messages
        user = self.loggedinbyconn[conn]                    
        blockedby = self.blocked[recipient]                 #Dictionary values are list of users who are blocking recipient
        blockedby.append(user)                              #Adds user to this list
    def unblock(self, conn, recipient):                     #Implements unblocking
        user = self.loggedinbyconn[conn]
        blockedby = self.blocked[recipient]                 
        blockedby.remove(user)
    def isblocked(self, conn, recipient):                   #Checks to see if a user is being blocked by the recipient
        user = self.loggedinbyconn[conn]
        blockedby = self.blocked[user]
        if recipient in blockedby:
            return True
        else:
            return False
    def logout(self, conn):                                 
        user = self.loggedinbyconn[conn]                    
        del self.loggedin[user]                             #Removes user from list of logged in users
        del self.loggedinbyconn[conn]
        now = time.time()
        self.loggedout[user] = time.time()                  #Keeps track of when the user logged out
    def update_lastactive(self, conn):                      #Updates the last time the user was active
        now = time.time()
        self.lastactive[conn] = now

#Main code for program
def main (port):
    HOST = ''
    PORT = int(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def timeout(servername):
        while True:
            now = time.time()
            try:
                for connection in servername.lastactive:
                    if now - servername.lastactive[connection] > TIME_OUT and servername.loggedinbyconn[connection] != []:
                        connection.sendall('You have been logged out due to inactivity.')
                        servername.logout(connection)
            except:
                pass
    try:
        s.bind((HOST,PORT))
        s.listen(1)
        print "Socket creation successful. IP address of the server is " + socket.gethostbyname(socket.gethostname())
        server = ChatServer()
        start_new_thread(timeout, (server,))
    except socket.error as msg:
        s.close()
        print "Socket creation unsuccessful"
    def clientthread (conn):                            #Starts new thread for each client
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                else:
                    command = string.split(data, ' ', 1)[0]
                    if command == 'login': 
                        content = string.split(data, ' ', 1)[1]
                        username = content.split()[0]
                        password = content.split()[1]
                        now = time.time()
                        if (conn,username) in server.loginblocked and now - server.loginblocked[(conn,username)] < BLOCK_TIME:   #Checks if address and username are blocked from logging in
                            conn.sendall('You have been blocked for too many incorrect tries.')
                        else:
                            if username in logindic and logindic[username] == password:         #If the username/password is correct
                                if username not in server.loggedin:                             #If user not logged in, can log in
                                    server.loggedin[username] = conn
                                    server.loggedinbyconn[conn] = username
                                    conn.sendall("Welcome to the simple chat server!\n")        
                                    server.update_lastactive(conn)     
                                    server.loginattempts[(conn,username)] = 0                    
                                    if server.storedmessages[username] != []:                   #If the user has any offline messages,
                                        for message in server.storedmessages[username]:         #server sends messages to user
                                            conn.sendall(message)
                                        del server.storedmessages[username]
                                else:                                                           #If user is already logged in, cannot log in
                                    conn.sendall('Sorry, that user is already logged in.')
                            else:
                                conn.sendall('Your username/password combination is incorrect.')
                                server.loginattempts[(conn,username)] += 1
                                if server.loginattempts[(conn,username)] >= 2:
                                    server.loginblocked[(conn,username)] = time.time()
                    elif command == 'loginblock':                                               #Blocks user from logging in for BLOCK_TIME
                            server.loginblocked[(conn, username)] = time.time() 
                    elif command == 'whoelse':                  #If command is whoelse, returns list of other logged in users
                        user = server.loggedinbyconn[conn]
                        reply = str(server.whoelse(conn))
                        server.update_lastactive(conn)
                        conn.sendall(reply)
                    elif command == 'wholasthr':                #If command is wholasthr, returns list of other users who were online in LAST_HOUR
                        reply = str(server.wholasthr(conn))
                        server.update_lastactive(conn)
                        conn.sendall(reply)
                    elif command == 'broadcast':                #Broadcasts message to all other users 
                        content = string.split(data, ' ', 1)[1]
                        user = server.loggedinbyconn[conn]
                        message = user + ': ' + content
                        all_other_users = server.whoelse(conn)
                        server.update_lastactive(conn)
                        if all_other_users:
                            for user in all_other_users:
                                connection = server.loggedin[user]
                                connection.sendall(message)
                        else:
                            conn.sendall('You are the only user in the chatroom.')      #Case where there is only one user in the room
                    elif command == 'message':                              #Sends a private message 
                        content = string.split(data, ' ', 1)[1]
                        recipient = string.split(content, ' ', 1)[0]
                        message = string.split(content, ' ', 1)[1]
                        server.update_lastactive(conn)
                        if not server.isblocked(conn, recipient):           #If the user is not blocked by the recipient,
                            sender = server.loggedinbyconn[conn]
                            if recipient in server.whoelse(conn):           #and the recipient is logged in,
                                recipient_connection = server.loggedin[recipient]
                                recipient_connection.sendall(sender + ': ' + message)   #sends message to recipient
                            elif recipient == sender:                       #Does not allow user to message themselves
                                conn.sendall('Error! You cannot send a message to yourself.')
                            else:                                           #If recipient not logged in, saves offline message for later
                                offline_message = [sender + ': ' + message]
                                server.storedmessages[recipient] += offline_message
                                conn.sendall(recipient + ' is offline. Your message will be delivered when that user logs in.')
                        else:                                               #If recipient is blocking user, user cannot send message.
                            conn.sendall('You cannot send any message to ' + recipient + '. You have been blocked by the user.')
                    elif command == 'block':                                #Blocks recipient
                        recipient = string.split(data, ' ', 1)[1]
                        user = server.loggedinbyconn[conn]
                        server.update_lastactive(conn)
                        if recipient in logindic:                           #Checks to make sure recipient exists
                            if user != recipient:                           #Checks to make sure you do not block yourself
                                server.block(conn, recipient)
                                conn.sendall('You have successfully blocked ' + recipient + ' from sending you messages.')
                            else:
                                conn.sendall('Error! You cannot block yourself!')
                        else:
                            conn.sendall('Error! That user does not exist!')    
                    elif command == 'unblock':                              #Unblocks recipient
                        recipient = string.split(data, ' ', 1)[1]
                        user = server.loggedinbyconn[conn]
                        server.update_lastactive(conn)
                        if server.isblocked(server.loggedin[recipient], user):  #Checks if recipient was blocked;
                            server.unblock(conn, recipient)                     #if so, unblocks recipient
                            conn.sendall('You have successfully unblocked ' + recipient + '.')
                        else:                                                   #If recipient was not blocked, informs user
                            conn.sendall('You cannot unblock ' + recipient + ' because you were not blocking that user.')
                    elif command == 'logout':                                   #Logs user out
                        server.logout(conn)
                        conn.sendall('You have been logged out.')
                        break
                    else:
                        conn.sendall('Error! That is not a valid command.')
            conn.close()
        except:
            import traceback
            print traceback.format_exc()
    while 1:
        conn, addr = s.accept()
        print 'Connected with ' + str(addr)
        start_new_thread(clientthread , (conn,))
    conn.close()
    s.close()
    sys.exit(0)

if __name__ == "__main__": main(sys.argv[1])
