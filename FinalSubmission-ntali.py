
#    15-112: Principles of Programming and Computer Science
#    Final Project: Implementing an online version of Stratego
#    Name      : Nour Ali
#    AndrewID  : Ntali

## ALL IMPORT STATEMENTS
import sys, socket, time, pygame
from pygame.locals import *
from tkinter import *
from tkinter import messagebox


########## SERVER COMMUNICATION FUNCTIONS - Networking ##########

# Helper for Task 1 - Left Rotate
def leftRotate(x, c):
    w = (x << c)&0xFFFFFFFF | (x >> (32-c)&0x7FFFFFFF>>(32-c))
    return w


# Helper for Task 1 - MD5 Algorithm
def MD5(M):
    s = []
    s[0:16] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22]
    s[16:32] = [5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20]
    s[32:48] = [4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23]
    s[48:64] = [6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    K = []
    K[0:4] = [ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee]
    K[4:8] = [ 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ]
    K[8:12] = [ 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ]
    K[12:16] = [ 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ]
    K[16:20] = [ 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ]
    K[20:24] = [ 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ]
    K[24:28] = [ 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ]
    K[28:32] = [ 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ]
    K[32:36] = [ 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ]
    K[36:40] = [ 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ]
    K[40:44] = [ 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ]
    K[44:48] = [ 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ]
    K[48:52] = [ 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ]
    K[52:56] = [ 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ]
    K[56:60] = [ 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ]
    K[60:64] = [ 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 ]

    # Initialize Variables
    a0 = int(0x67452301)
    b0 = int(0xefcdab89)
    c0 = int(0x98badcfe)
    d0 = int(0x10325476)
    A = a0
    B = b0
    C = c0
    D = d0


    # Main Loop
    for i in range(64): 

        if (0 <= i) and (i <= 15):
            F = (B & C) | ((~ B) & D)
            F = F & 0xFFFFFFFF
            g = i

        elif (16 <= i) and (i <= 31):
            F = (D & B) | ((~ D) & C)
            F = F & 0xFFFFFFFF
            g = (5*i + 1) % 16

        elif (32 <= i) and (i <= 47):
            F = B ^ C ^ D
            F = F & 0xFFFFFFFF
            g = (3*i + 5) % 16

        elif (48 <= i) and (i <= 63):
            F = C ^ (B | (~ D))
            F = F & 0xFFFFFFFF
            g = (7*i) % 16

        dTemp = D
        D = C
        C = B
        B = B + leftRotate((A + F + K[i] + M[g]), s[i])
        B = B & 0xFFFFFFFF
        A = dTemp


    # Add this chunk's hash to result so far:
    a0 = (a0 + A) & 0xFFFFFFFF
    b0 = (b0 + B) & 0xFFFFFFFF
    c0 = (c0 + C) & 0xFFFFFFFF
    d0 = (d0 + D) & 0xFFFFFFFF

    result = str(a0) + str(b0) + str(c0) + str(d0)

    return result



# Helper for Task 1 - Creating Message Digest
def encrypt(password, challenge):

    # Step 1 - Creating Block
    n = len(password)
    m = len(challenge)
    message = str(password) + str(challenge)
    nm = str(n+m)
    while len(nm) < 3:
        nm = "0" + nm
    zeroes = 512 - (n+m) - 4
    block = message + "1" + ("0" * zeroes) + nm

    # Step 2 - Creating M
    M = []
    x = 0
    for i in range(16):
        chunck = 0
        for i in range(32):
            chunck = chunck + ord(block[x])
            x = x + 1        
        M.append(chunck)

    # Step 3 - Apply MD5

    result = MD5(M)

    # Digest is ready
    return (result)
        

# Task 0 - Establishing Socket Connection
def StartConnection (IPAddress, PortNumber):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((IPAddress, PortNumber))
    return s


# Task 1 - User Authentication Login
def login (s, username, password):

    # Communicate with server to recieve chellenge for encryption
    s.send(b"LOGIN "+bytes(username,"utf-8")+b"\n")
    response = s.recv(1000)

    # Calculating Message Digest (using helpers)
    response = str(response, "utf-8")
    msg = response.split()

    digest = encrypt(password, msg[2])
    
    # Confirming message digest with server
    s.send(b"LOGIN "+bytes(username,"utf-8")+ b" "+bytes(digest,"utf-8")+b"\n")
    success = s.recv(1000)
    success = str(success, "utf-8")
    success = success.split()
   
    if success[0] == "WRONG":
        return False
    else:
        return True


# Task 2a - Accessing List of Users
def getUsers(s):

    # Communicate with server to recieve list of users
    s.send(b"@users\n")
    response = s.recv(6)
    size = int(str(response, "utf-8")[1:])
    fullResponse = str(s.recv(size), "utf-8")

    userList = fullResponse.split('@')

    # Return list of Users
    return (userList[3:])


# Task 2b - Accessing List of Friends
def getFriends(s):

    # Communicate with server to recieve list of friends
    s.send(b"@friends\n")
    response = s.recv(6)
    size = int(str(response, "utf-8")[1:])
    fullResponse = str(s.recv(size), "utf-8")
    
    friendList = fullResponse.split('@')

    # Return list of Friends
    return (friendList[3:])


# Task 2c - Accessing List of Friend Requests
def getRequests(s):

    # Communicate with server to recieve list of friend requests
    s.send(b"@rxrqst\n")
    response = s.recv(6)
    size = int(str(response, "utf-8")[1:])
    fullResponse = str(s.recv(size), "utf-8")
    
    requestList = fullResponse.split('@')

    # Return list of Friend Requests
    return (requestList[2:])


# Task 3a - Sending Friend Requests
def sendFriendRequest(s, friend):
    
    # Communicate with server to send a friend request
    size = str(22 + int(len(friend)))
    size = (5-len(size)) * "0" + size
    s.send(b"@"+bytes(size,"utf-8")+b"@request@friend@"+bytes(friend,"utf-8")+b"\n")

    response = str(s.recv(1000), "utf-8").split('@')

    # Confirming request
    if response[2] == "ok":
        return True
    else:
        return False


# Task 3b - Accepting Friend Requests
def acceptFriendRequest(s, friend):

    # Communicate with server to accept a friend request
    size = str(22 + int(len(friend)))
    size = (5-len(size)) * "0" + size
    s.send(b"@"+bytes(size,"utf-8")+b"@accept@friend@"+bytes(friend,"utf-8")+b"\n")
    
    response = str(s.recv(1000), "utf-8").split('@')

    # Confirming request
    if response[2] == "ok":
        return True
    else:
        return False


# Task 4 - Sending Messages
def sendMessage(s, friend, message):

    # Communicate with server to accept a friend request
    size = str(16 + int(len(friend)) + int(len(message)) )
    size = (5-len(size)) * "0" + size
    s.send(b"@"+bytes(size,"utf-8")+b"@sendmsg@"+bytes(friend,"utf-8")+b"@"+bytes(message,"utf-8")+b"\n")

    response = str(s.recv(1000), "utf-8").split('@')

    # Confirming request
    if len(response)>= 2 and response[2] == "ok":
        return True
    else:
        return False


# Task 5 - Recieving Messages
def getMail(s):

    # Communicate with server to recieve mail
    s.send(b"@rxmsg\n")
    response = s.recv(6)
    size = int(str(response, "utf-8")[1:])
    fullResponse = str(s.recv(size), "utf-8")

    ## Arranging Messages
    r = fullResponse.split('@')
    messages = []
    files = []

    startMsg = 0
    startFile = 0

    for i in range(len(r)):
        # Finding start of messages
        if (r[i] == "msg") and (startMsg == 0):         
            startMsg = i + 1

        #Finding start of files
        if r[i] == "file" and (startFile == 0):
            startFile = i + 1

    
    # If any Messages were sent
    if startMsg != 0:

        # If no files were sent
        if startFile == 0:
            startFile = len(r)

        # Append each Message to list with sender
        for i in range(startMsg, startFile, 3):

            # List of Messages
            entry = (r[i], r[i+1])
            messages.append(entry)

    # If any files were sent
    if startFile != 0:

        # Append each Filename to list with sender
        for i in range(startFile, len(r), 4):

            # List of Files
            entry = (r[i], r[i+1])
            files.append(entry)

            # Saving File
            fileName = r[i+1]
            fileContent = r[i+2]

            file = open(str(fileName), "w+")                                                       
            file.write(fileContent)
            file.close()

    return (messages)


########## LOGIN AND HOMEPAGE INTERFACE ##########

# Task 1 - The Login Screen
# This class controls the entire setup of the login screen
class loginWnd():
    def __init__(self, root):

        # Connect to the server at IP Address 86.36.46.10
        # and port number 15112
        self.s = StartConnection("86.36.46.10", 15112)
        self.mainW = root
        self.mainFrame = Frame(root)
        self.mainFrame.pack()

        # First Entry Box - Username
        self.Lbl1 = Label(self.mainFrame, text = "Username:")
        self.Lbl1.pack()

        self.Canv1 = Canvas(self.mainFrame, width = 150, height = 30)
        self.username = Entry(self.mainFrame)
        self.Canv1.pack()
        self.Canv1.create_window(75, 15, window = self.username)

        # Second Entry Box - Password
        self.Lbl2 = Label(self.mainFrame, text = "Password:")
        self.Lbl2.pack()

        self.Canv2 = Canvas(self.mainFrame, width = 150, height = 30)
        self.password = Entry(self.mainFrame, show = "*")
        self.Canv2.pack()
        self.Canv2.create_window(75, 15, window=self.password)

        # Login Button - calls login function from HW7
        self.btn1 = Button(self.mainFrame, text = "OK", command = self.verifyUser)
        self.btn1.pack()

        self.loginSuccess = False
        self.me = ""
        

    # Verifying entered Username & Password
    def verifyUser(self):
        u = self.username.get()
        p = self.password.get()

        verify = login(self.s, u, p)

        # If username & password correct
        # Close login window & set success as true
        if verify == True:
            self.loginSuccess = True
            self.me = u

        self.mainW.destroy()


# Task 2 - The Main Chat Client Screen
# This class controls the entire setup of the main chat client screen
class userWnd():
    def __init__(self, root, socket, me):
        self.s = socket
        self.mainW = root
        self.username = me
        self.mainFrame = Frame(root)
        self.mainFrame.pack()

        # First Section - Users List & Sending Friend Requests
        self.Lbl1 = Label(self.mainFrame, text = "All Users:")
        self.Lbl1.grid(row = 0, column = 0)

        self.List1 = Listbox(self.mainFrame, height = 20)
        self.List1.grid(row = 1, column = 0)

        self.btn1 = Button(self.mainFrame, text = "Send Friend Request", command = self.sendFriendReq)
        self.btn1.grid(row = 2, column = 0)        

        # Second Section - Friends List & Sending Game Requests
        self.Lbl2 = Label(self.mainFrame, text = "Your Friends:")
        self.Lbl2.grid(row = 0, column = 1)

        self.List2 = Listbox(self.mainFrame, height = 20)
        self.List2.grid(row = 1, column = 1)

        self.btn2 = Button(self.mainFrame, text = "Send Game Request", command = self.sendGameReq)
        self.btn2.grid(row = 2, column = 1)

        # Third Section - Pending Friend Requests List & Accepting Friend Requests
        self.Lbl3 = Label(self.mainFrame, text = "Pending Friend Requests:")
        self.Lbl3.grid(row = 0, column = 2)

        self.List3 = Listbox(self.mainFrame, height = 20)
        self.List3.grid(row = 1, column = 2)

        self.btn3 = Button(self.mainFrame, text = "Accept Friend Request", command = self.acceptFriendReq)
        self.btn3.grid(row = 2, column = 2)

        # Fourth Section - Pending Game Requests List & Accepting Game Requests
        self.Lbl4 = Label(self.mainFrame, text = "Pending Game Requests:")
        self.Lbl4.grid(row = 0, column = 3)

        self.List4 = Listbox(self.mainFrame, height = 20)
        self.List4.grid(row = 1, column = 3)

        self.btn4 = Button(self.mainFrame, text = "Accept Game Request", command = self.acceptGameReq)
        self.btn4.grid(row = 2, column = 3)

        # Keeping track of all open chat windows
        self.gamesOpen = {}

        # Keeping track of all game requests that I sent
        self.gameReqSent = []

        # Keeping track of all game requests that I recieved
        self.gameReqRecieved = []

        # Protocol for closing window
        self.mainW.protocol("WM_DELETE_WINDOW", self.onClosing)

        self.mainFrame.after(0, self.displayUsers)
        self.mainFrame.after(0, self.displayFriends)
        self.mainFrame.after(0, self.displayFriendReq)
        self.mainFrame.after(0, self.displayGameReq)
        self.mainFrame.after(0, self.getMessages)


    # Displays list of Active Users in First Section
    def displayUsers(self):

        Users = getUsers(self.s)

        for i in range(len(Users)):
            self.List1.insert(i, Users[i])


    # Displays list of Friends in Second Section       
    def displayFriends(self):
        self.List2.delete(0, END)

        Friends = getFriends(self.s)

        for i in range(len(Friends)):
            self.List2.insert(i, Friends[i])

        # Continously Update the Friend List every 8 seconds
        self.mainFrame.after(8000, self.displayFriends)
        

    # Displays list of Friend Requests in Third Section   
    def displayFriendReq(self):
        self.List3.delete(0, END)

        Requests = getRequests(self.s)

        for i in range(len(Requests)):
            self.List3.insert(i, Requests[i])

        # Continously Update the Requests List every 8 seconds
        self.mainFrame.after(8000, self.displayFriendReq)


    # Displays list of Game Requests in Fourth Section   
    def displayGameReq(self):
        self.List4.delete(0, END)

        Requests = self.gameReqRecieved

        for i in range(len(Requests)):
            self.List4.insert(i, Requests[i])

        # Continously Update the Requests List every 8 seconds
        self.mainFrame.after(8000, self.displayGameReq)


    # Sending a Friend Request to selected user in User List       
    def sendFriendReq(self):
        selection = self.List1.curselection()
        friend = self.List1.get(selection)

        r = sendFriendRequest(self.s, friend)

        if r == True:
            messagebox.showinfo("Success","Friend Request succesfully sent to "+friend)
        else:
            messagebox.showinfo("Error","Error adding "+friend+". Please try again.")


    # Starting a Game with selected user in Friends List
    def sendGameReq(self):
        selection = self.List2.curselection()
        friend = self.List2.get(selection)

        # No Current game running
        if friend not in self.gamesOpen:

            # No valid game request 
            if friend not in self.gameReqSent:

                # A game request is sent to friend
                if sendMessage(self.s, friend, "GAMEREQUEST"):
                    messagebox.showinfo("Success","Game Request successfuly sent to "+friend+".")
                    self.gameReqSent.append(friend)

            # A Valid game request already exists                
            else:
                messagebox.showinfo("Error","Game request already sent to "+friend+".")

        # A current game running
        else:
            messagebox.showinfo("Error","Game window with "+friend+" already open.")


    # Accepting a Friend Request from selected user in Pending Requests List       
    def acceptFriendReq(self):
        selection = self.List3.curselection()
        friend = self.List3.get(selection)

        r = acceptFriendRequest(self.s, friend)
        
        if r == True:
            messagebox.showinfo("Success","Friend Request from " + friend + " successfully accepted")
        else:
            messagebox.showinfo("Error","Error accepting friend request from " + friend + ". Please try again.")

        self.displayFriendReq()

    # Accepting a Game Request from selected user in Pending Requests List       
    def acceptGameReq(self):
        selection = self.List4.curselection()
        friend = self.List4.get(selection)

        r = sendMessage(self.s, friend, "ACCEPTED")

        if r == True:
            messagebox.showinfo("Success","Game Request from " + friend + " successfully accepted")
            self.gameReqRecieved.remove(friend)
            self.displayGameReq()
            gameWnd = StrategoGame(self.s, friend, self.username, friend, self)
            self.gamesOpen[friend]= gameWnd
            gameWnd.setUpScreen()
            
        else:
            messagebox.showinfo("Error","Error accepting game request from " + friend + ". Please try again.")

        self.displayGameReq()

    # Conitnuous checking for messages
    def getMessages(self):
        
        Messages = getMail(self.s)

        # For each message check if it is a request, acceptance, cancelation, gamemove
        for (u, m) in Messages:
            msg = m.split()
            
            # Getting requests
            if msg[0] == "GAMEREQUEST":
                self.gameReqRecieved.append(u)
                self.displayGameReq()

            # Deleting requests
            if u in self.gameReqRecieved:
                if msg[0] == "CANCELLED":
                    self.gameReqRecieved.remove(u)
                    self.displayGameReq()
                
            # Waiting for acceptance
            if u in self.gameReqSent:
                # If acceptance is recieved create a game object
                    if msg[0] == "ACCEPTED":
                        messagebox.showinfo("Accepted","Game request to " + u + " was accepted.")
                        self.gameReqSent.remove(u)
                        gameWnd = StrategoGame(self.s, self.username, self.username, u, self)
                        self.gamesOpen[u]= gameWnd
                        gameWnd.setUpScreen()
                    if msg[0] == "DECLINED":
                        messagebox.showinfo("Declined","Game request to " + u + " was declined.")
                        self.gameReqSent.remove(u)

            # Game Currently running, let gameClass handle it
            if u in self.gamesOpen:
                self.gamesOpen[u].handleMsg(m)                                

        # Only recall function if no games are open         
        if self.gamesOpen == {}:            

            # Continously check for messages every 1 second
            self.mainFrame.after(1000, self.getMessages)


    # Before closing, cancel any sent requests and decline any pending requests
    def onClosing(self):
        sentReq = self.gameReqSent
        recReq = self.gameReqRecieved   
        for i in sentReq:
            sendMessage(self.s, i, "CANCELLED")
        for i in recReq:
            sendMessage(self.s, i, "DECLINED")
        self.mainW.destroy()



########## GAME LOGIC FUNCTIONS ##########

## GAME PIECE CLASS - Creates a game piece
class gamePiece():
    def __init__(self, name, rank, img, movable=True, status=True):
        self.name = name
        self.rank = rank
        self.img = pygame.image.load(img)
        self.movable = movable
        self.status = status

## ARMY CLASS - Creates an army of game pieces
class army():
    def __init__(self):
        self.soldiers = []
        # Add Flag - Rank 0
        self.soldiers.append(gamePiece("Flag", 0, "rank0.png", False))
        # Add Bombs - Rank -1
        self.soldiers = self.soldiers + [gamePiece("Bomb", -1,"rank-1.png", False) for i in range(6)]
        # Add Marshal - Rank 1
        self.soldiers.append(gamePiece("Marshal", 1, "rank1.png"))
        # Add General - Rank 2
        self.soldiers.append(gamePiece("General", 2, "rank2.png"))
        # Add Colonels - Rank 3
        self.soldiers = self.soldiers + [gamePiece("Colonel", 3, "rank3.png") for i in range(2)]
        # Add Major - Rank 4
        self.soldiers = self.soldiers + [gamePiece("Major", 4, "rank4.png") for i in range(3)]
        # Add Captains - Rank 5
        self.soldiers = self.soldiers + [gamePiece("Captain", 5, "rank5.png") for i in range(4)]
        # Add Lieutenants - Rank 6
        self.soldiers = self.soldiers + [gamePiece("Lieutenant", 6, "rank6.png") for i in range(4)]
        # Add Sergeants - Rank 7
        self.soldiers = self.soldiers + [gamePiece("Sergeant", 7, "rank7.png") for i in range(4)]
        # Add Miners - Rank 8
        self.soldiers = self.soldiers + [gamePiece("Miner", 8, "rank8.png") for i in range(5)]
        # Add Scouts - Rank 9
        self.soldiers = self.soldiers + [gamePiece("Scout", 9, "rank9.png") for i in range(8)]
        # Add Spy - Rank 10
        self.soldiers.append(gamePiece("Spy", 10, "rank10.png"))


## GAME BOARD CLASS - Creates & Manages the status of the game board
class gameBoard():
    def __init__ (self):
        self.space = pygame.image.load("space.png")
        self.board = [[ self.space for i in range(10)] for i in range(10)]

        # Initializes opponents side of the board
        self.X = pygame.image.load("X.png")
        for i in range(4):
            for j in range(10):
                self.board[i][j] = self.X

        # Initializes 'lake' in middle of board
        self.lake = pygame.image.load("lake.png")
        self.board[4][2] = self.lake
        self.board[4][3] = self.lake
        self.board[5][2] = self.lake
        self.board[5][3] = self.lake
        self.board[4][6] = self.lake
        self.board[4][7] = self.lake
        self.board[5][6] = self.lake
        self.board[5][7] = self.lake


    # Ensures each soldier is insert into a valid place
    def validSetUp(self, x, y):
        if (x < 6) or (x > 9) or (y < 0) or (y > 9):
            print("Out of range")
            return False
        empty = self.isNotOccupied(x,y)
        return empty

    # Returns object at location x, y
    def whichPiece(self, x, y):
        return self.board[int(x)][int(y)]

    # Determines if postion is occupied in board
    def isNotOccupied(self, x, y):
        if self.board[x][y] == self.space:
            return True
        print("Occupied")
        return False

    # Places a game piece into an empty position 
    def movePiece(self,curX, curY, newX, newY):
        self.board[int(newX)][int(newY)] = self.whichPiece(int(curX), int(curY))
        self.board[int(curX)][int(curY)] = self.space

    # Removes a piece from the game board
    def removePiece(self, curX, curY):
        piece = self.whichPiece(int(curX), int(curY))
        if type(piece) is gamePiece:
            piece.status = False
        self.board[int(curX)][int(curY)] = self.space
    
    # Checks if a possible move is valid
    def isValidMove(self, curX, curY, newX, newY):
            
        # Check that piece is of my army
        piece = self.whichPiece(curX, curY)

        if not(type(piece) is gamePiece):
            print("ERROR: This is not your piece!")
            return False

        # Check that piece is movable
        if piece.movable == False:
            print("ERROR: This piece is not movable!")
            return False

        # Check that new position is unoccupied
        if self.isNotOccupied(newX, newY) == False:
            print("ERROR: This position is occupied!")
            return False
        
        # Check that new position is adjacent (except if 9)
        distanceX = abs(newX - curX)
        distanceY = abs(newY - curY)

        # Moving in 2 directions (diagonal)
        if (distanceX > 0) and (distanceY > 0):
            print("ERROR: No diagonal moves!")
            return False

        # More than one step in any direction & not 9
        if ((distanceX > 1) or (distanceY > 1)) and (piece.rank != 9):
            print("ERROR: You cannot move this piece more than 1 step!")
            return False

        # Obstructions moving vertically
        if distanceY == 0:
            # Moving DOWN
            if curX < newX:
                for i in range(curX + 1, newX):
                    if self.isNotOccupied(i, curY) == False:
                        print("ERROR: Another piece is in the way!")
                        return False

            # MOVING UP
            else:
                for i in range(newX + 1, curX):
                    if self.isNotOccupied(i, curY) == False:
                        print("ERROR: Another piece is in the way!")
                        return False

        # Obstructions moving horizontally
        if distanceX == 0:
            # Moving RIGHT
            if curY < newY:
                for i in range(curY + 1, newY):
                    if self.isNotOccupied(curX, i) == False:
                        print("ERROR: Another piece is in the way!")
                        return False

            # MOVING LEFT
            else:
                for i in range(newY + 1, curY):
                    if self.isNotOccupied(curX, i) == False:
                        print("ERROR: Another piece is in the way!")
                        return False

        print("VALID MOVE")
        return True


    # Checks if a possible attack is valid    
    def isValidAttack(self, curX, curY, newX, newY):
            
        # Check that attacking piece is of my army
        piece = self.whichPiece(curX, curY)
        if not(type(piece) is gamePiece):
            print("ERROR: This is not your piece!")
            return False

        # Check that attacking piece is movable
        if piece.movable == False:
            print("ERROR: This piece is not movable!")
            return False

        # Check that new position is occupied by opponent
        opp = self.whichPiece(newX, newY)
        if opp != self.X:
            print("ERROR: You may not attack this location!")
            return False
        
        # Check that new position is adjacent
        distanceX = abs(newX - curX)
        distanceY = abs(newY - curY)

        # Adjacent attacks only
        if (distanceX > 1) or (distanceY > 1): 
            print("ERROR: Must attack an adjacent piece!")
            return False

        # Attacking in 2 directions (diagonal)
        if (distanceX == 1) and (distanceY == 1):
            print("ERROR: No diagonal attacks!")
            return False

        print("VALID ATTACK")
        return True

    # Returns the result of an attack
    def attackResult(self, myRank, oppRank):
        if oppRank == 0:
            return "YOUWON"
        if myRank == 10 and oppRank == 1:
            return myRank
        if myRank == 1 and oppRank == 10:
            return myRank       
        if myRank != 8 and oppRank == -1:
            return oppRank
        if myRank == 8 and oppRank == -1:
            return myRank
        if myRank == oppRank:
            return "DRAW"
        if oppRank == 0:
            return myRank
        if myRank < oppRank:
            return myRank
        if myRank > oppRank:
            return oppRank


########## GAME BOARD INTERFACE FUNCTIONS ##########

# Setting up color constants
#            R    G    B
GRAY     = (100, 100, 100)
NAVYBLUE = ( 60,  60, 100)
WHITE    = (255, 255, 255)
RED      = (255,   0,   0)
GREEN    = (  0, 255,   0)
BLUE     = (  0,   0, 255)
YELLOW   = (255, 255,   0)
ORANGE   = (255, 128,   0)
PURPLE   = (100,   0, 100)
CYAN     = (  0, 255, 255)
BLACK    = (  0,   0,   0)
WHITE    = (255, 255, 255)
PINK     = (255, 87, 168)
CLEAR    = (  0,   0,   0,  0)
LIGHTPURPLE = (100,   0, 100, 80)


FPS = 30 # frames per second, the general speed of the program
WINDOWWIDTH = 1000 # size of window's width in pixels
WINDOWHEIGHT = 790 # size of windows' height in pixels
BOXHEIGHT = 75 # size of box height & width in pixels
BOXWIDTH = 70 # size of box height & width in pixels
GAPSIZE = 2 # size of gap between boxes in pixels
BOARDWIDTH = 10 # number of columns of icons
BOARDHEIGHT = 10 # number of rows of icons
XMARGIN = int((WINDOWWIDTH - (BOARDWIDTH * (BOXWIDTH + GAPSIZE))) // 2)
YMARGIN = int((WINDOWHEIGHT - (BOARDHEIGHT * (BOXHEIGHT + GAPSIZE))) // 2)

BGCOLOR1 = NAVYBLUE
BGCOLOR2 = PURPLE
LIGHTBGCOLOR = GRAY
BOXCOLOR = WHITE
MOVEHLC = CYAN
ATTACKINGHLC = ORANGE
ATTACKERHLC = RED
ATTACKEDHLC = YELLOW


##### MAIN GAME CLASS #####
class StrategoGame():
    def __init__(self, s, req, player1, player2, home):
        # Socket connection
        self.s = s
        # Players
        self.reqPlayer = req
        self.me = player1
        self.opponent = player2
        # Army & Board
        self.myArmy = army()
        self.theBoard = gameBoard()
        # Board Set-Up
        self.meReady = False
        self.oppReady = False
        # Game Turns
        self.myTurn = False
        self.oppTurn = False
        # Attack Info
        self.attackInfo = ( 0, 0, 0, 0, 0)
        self.attackingRank = 0
        self.myRankAttacked = 0
        # Home Window
        self.home = home
        # End of Game
        self.gameEnded = False
        # Game Surface
        self.gameDisplay = None
        # All Images
        self.images = {
            0 : pygame.image.load("rank0.png"),
            -1 : pygame.image.load("rank-1.png"),
            1 : pygame.image.load("rank1.png"),
            2 : pygame.image.load("rank2.png"),
            3 : pygame.image.load("rank3.png"),
            4 : pygame.image.load("rank4.png"),
            5 : pygame.image.load("rank5.png"),
            6 : pygame.image.load("rank6.png"),
            7 : pygame.image.load("rank7.png"),
            8 : pygame.image.load("rank8.png"),
            9 : pygame.image.load("rank9.png"),
            10 : pygame.image.load("rank10.png")
            }


    # Convert board coordinates to pixel coordinates
    def leftTopCoordsOfBox(self, boxx, boxy):        
        left = boxx * (BOXWIDTH + GAPSIZE) + XMARGIN
        top = boxy * (BOXHEIGHT + GAPSIZE) + YMARGIN
        return (left, top)


    # Convert pixel coordinates to board coordinates   
    def getBoxAtPixel(self, x, y):      
        for boxx in range(BOARDWIDTH):
            for boxy in range(BOARDHEIGHT):
                left, top = self.leftTopCoordsOfBox(boxx, boxy)                
                boxRect = pygame.Rect(left, top, BOXWIDTH, BOXHEIGHT)

                # Returns location on board
                if boxRect.collidepoint(x, y):
                    return (boxx, boxy)
        return (None, None)


    # Draws the current state of the board
    def drawBoard(self,displaySurf):
        pygame.draw.rect(displaySurf, BGCOLOR2, (0, 30, 120, 800))
        for boxx in range(BOARDWIDTH):
            for boxy in range(BOARDHEIGHT):
                left, top = self.leftTopCoordsOfBox(boxx, boxy)
                pygame.draw.rect(displaySurf, BOXCOLOR, (left, top, BOXWIDTH, BOXHEIGHT))

                # Displays correct image in place
                icon = self.theBoard.board[boxy][boxx]
                if type(icon) is gamePiece:
                    displaySurf.blit(icon.img, (left+15, top+5))
                else:
                    displaySurf.blit(icon, (left+15, top+5))
                    

    # Draws a highlight around selected box 
    def drawHighlightBox(self, displaySurf, boxx, boxy, color):
        left, top = self.leftTopCoordsOfBox(boxx, boxy)
        pygame.draw.rect(displaySurf, color, (left + 2, top + 2, BOXWIDTH-4 , BOXHEIGHT-4 ), 4)


    # When a piece of mine is getting attacked
    def gettingAttacked(self, oppRank, oppX, oppY, curX, curY):
        displaySurf = self.gameDisplay
        
        # Highlight attacking piece        
        self.drawHighlightBox(displaySurf, oppY, oppX, ATTACKERHLC)
        pygame.display.update()

        # One second Pause
        pygame.time.wait(1000)

        # Highlight piece getting attacked
        self.drawHighlightBox(displaySurf, curY, curX, ATTACKEDHLC)
        pygame.display.update()

        # One second Pause
        pygame.time.wait(1000)

        # Reveal attacking piece
        X = self.images[oppRank]
        left, top = self.leftTopCoordsOfBox(oppY, oppX)
        displaySurf.blit(X, (left+15, top+5))
        self.drawHighlightBox(displaySurf, oppY, oppX, ATTACKERHLC)
        pygame.display.update()

        # Four second Pause
        pygame.time.wait(4000)
        self.drawBoard(displaySurf)


    # When I am attacking an opponent's piece
    def attacking(self, oppRank, curX, curY, oppX, oppY):
        displaySurf = self.gameDisplay
        
        # Highlight attacking piece     
        self.drawHighlightBox(displaySurf, curY, curX, ATTACKERHLC)
        pygame.display.update()

        # One second Pause
        pygame.time.wait(1000)

        # Highlight piece getting attacked
        self.drawHighlightBox(displaySurf, oppY, oppX, ATTACKEDHLC)
        pygame.display.update()

        # One second Pause
        pygame.time.wait(1000)

        # Reveal attacking piece
        X = self.images[oppRank]
        left, top = self.leftTopCoordsOfBox(oppY, oppX)
        displaySurf.blit(X, (left+15, top+5))
        self.drawHighlightBox(displaySurf, oppY, oppX, ATTACKEDHLC)
        pygame.display.update()

        # Four second Pause
        pygame.time.wait(4000)
        self.drawBoard(displaySurf)


    # Allows User to set up pieces on board
    def setUpScreen(self):
        pygame.init()
        FPSCLOCK = pygame.time.Clock()
        DISPLAYSURF = pygame.display.set_mode((WINDOWWIDTH, WINDOWHEIGHT))
        self.gameDisplay = DISPLAYSURF

        pygame.display.set_caption('Stratego - Set up Screen for '+ self.me)
        DISPLAYSURF.fill(BGCOLOR1) # drawing the window

        # Draws empty initialized board
        self.drawBoard(DISPLAYSURF)

        mouseX = 0 # used to store x coordinate of mouse event
        mouseY = 0 # used to store y coordinate of mouse event

        # Displays next soldier to be placed
        fontObj = pygame.font.Font('freesansbold.ttf', 18)
        textSurfaceObj = fontObj.render('Next Soldier:', True, BLACK, WHITE)
        textRectObj = textSurfaceObj.get_rect()
        textRectObj.center = (60, 12)
        DISPLAYSURF.blit(textSurfaceObj, textRectObj)
        
        soldiersPlaced = 0
        DISPLAYSURF.blit(self.myArmy.soldiers[soldiersPlaced].img, (10, 30))

        # SetUp Loop
        while True:
            mouseClicked = False
            for e in pygame.event.get():
                # If the user exits the window, alert opponent & clear from gamesOpen{}
                if e.type == QUIT or (e.type == KEYUP and e.key == K_ESCAPE):
                    print("Game closed")
                    sendMessage(self.s, self.opponent, "CLOSED")
                    if self.opponent in self.home.gamesOpen:
                        del self.home.gamesOpen[self.opponent]
                    pygame.quit()
                    sys.exit()

                elif e.type == MOUSEMOTION:
                    mouseX, mouseY = e.pos
        
                elif e.type == MOUSEBUTTONUP:
                    mouseX, mouseY = e.pos
                    mouseClicked = True
                    
            # Determine location of click on board
            boxy, boxx = self.getBoxAtPixel(mouseX, mouseY)
            
            if boxx != None and boxy != None:

                # If click is on a box in the board
                if soldiersPlaced <= 39 and mouseClicked == True:

                    #Check is Valid Location to place soldier
                    validSpot = self.theBoard.validSetUp(boxx, boxy)
                    if validSpot:                      

                        # Display image of soldier on the correct box on grid
                        self.theBoard.board[boxx][boxy] = self.myArmy.soldiers[soldiersPlaced]
                        self.drawBoard(DISPLAYSURF)                 
                        soldiersPlaced += 1

                        # Display next soldier in pile to be placed
                        if soldiersPlaced <= 39:
                            DISPLAYSURF.blit(self.myArmy.soldiers[soldiersPlaced].img, (10, 30))

                        # Once all soldiers have been placed
                        # Send Confirmation to opponent
                        if soldiersPlaced == 40:
                            pygame.display.update()
                            sendMessage(self.s, self.opponent, "BOARDSETUP")
                            self.meReady = True
                            print("MY SETUP COMPLETE")
                            

            # Call home window's getMessage Function                
            self.home.getMessages()

            # If both opponent & I are ready, begin game
            if self.meReady == True and self.oppReady == True:
                print("Both ready!")
                self.beginGame()
                pygame.quit()
                break

            pygame.display.update()
            FPSCLOCK.tick(FPS)

            
    # Main Game Function
    def beginGame(self):
        print("Let's Start!")
        pygame.init()
        FPSCLOCK = pygame.time.Clock()
        GAMESURF = pygame.display.set_mode((WINDOWWIDTH, WINDOWHEIGHT))
        self.gameDisplay = GAMESURF
        
        pygame.display.set_caption('Stratego - Game Screen for '+ self.me)
        GAMESURF.fill(BGCOLOR2) # drawing the window

        # Draws empty initialized board
        self.drawBoard(GAMESURF)

        mouseX = 0 # used to store x coordinate of mouse event
        mouseY = 0 # used to store y coordinate of mouse event

        firstLeftClick = False
        firstRightClick = False

        # To start game, determine requesting player
        if self.reqPlayer == self.me:
            self.myTurn = True
            print("This is your turn")
        elif self.reqPlayer == self.opponent:
            self.oppTurn = True
            print("Waiting for opponent to make move...")

        # Main Game Loop
        while True:
            mouseClicked = False
            for e in pygame.event.get():

                # If the user exits the window, alert opponent & clear from gamesOpen{}
                if e.type == QUIT or (e.type == KEYUP and e.key == K_ESCAPE):
                    print("Game closed")
                    sendMessage(self.s, self.opponent, "CLOSED")
                    if self.opponent in self.home.gamesOpen:
                        del self.home.gamesOpen[self.opponent]
                    pygame.quit()
                    sys.exit()

                elif e.type == MOUSEMOTION:
                    mouseX, mouseY = e.pos
        
                elif e.type == MOUSEBUTTONUP:
                    mouseX, mouseY = e.pos
                    if e.button == 1:
                        click = "LEFT"
                    elif e.button == 3:
                        click = "RIGHT"
                    
                    mouseClicked = True

            # First check if game has ended
            self.gameStatus()
            if self.gameEnded:
                pass
            
            # Only act on events if it is my turn
            elif self.myTurn == True:

                # Continously display board until I make my first click        
                if firstLeftClick == False and firstRightClick == False:
                    self.drawBoard(GAMESURF)
                    # Displays message "Opponent's move"
                    fontObj = pygame.font.Font('freesansbold.ttf', 50)
                    textSurfaceObj = fontObj.render("YOUR TURN....", True, PINK, WHITE)
                    textSurfaceObj = pygame.transform.rotate(textSurfaceObj, 90)
                    textRectObj = textSurfaceObj.get_rect()
                    textRectObj.center = (60, 400)
                    GAMESURF.blit(textSurfaceObj, textRectObj)

                # Determine location of click on board
                boxy, boxx = self.getBoxAtPixel(mouseX, mouseY)

                # If click is made on board
                if boxx != None and boxy != None and mouseClicked:

                    # If a left click is made
                    if click == "LEFT":
                        
                        firstLeftClick = not firstLeftClick

                        # If both left & right have been clicked consecutivley, cancel
                        if firstLeftClick and firstRightClick:
                            firstLeftClick = False
                            firstRightClick = False
                        
                        # If this is first click:
                        elif firstLeftClick:

                            # Save board location
                            curX, curY = boxx, boxy
                            self.drawHighlightBox(GAMESURF, boxy, boxx, MOVEHLC)

                        # If this is second click
                        elif not firstLeftClick:

                            # Save board location
                            newX, newY = boxx, boxy

                            # Now that two clicks have been made, check if move is valid
                            validAction = self.theBoard.isValidMove(curX, curY, newX, newY)                        

                            # If move is valid make the move
                            if validAction == True:
                                self.makeMove(curX, curY, newX, newY)
                                self.drawBoard(GAMESURF)
                                self.myTurn = False
                                self.oppTurn = True
                            else:
                                self.drawBoard(GAMESURF)

                    # If a right click is made
                    elif click == "RIGHT":
                        
                        firstRightClick = not firstRightClick

                        # If both left & right have been clicked consecutivley, cancel
                        if firstLeftClick and firstRightClick:
                            firstLeftClick = False
                            firstRightClick = False

                        # If this is first click:
                        elif firstRightClick:

                            # Save board location
                            curX, curY = boxx, boxy
                            self.drawHighlightBox(GAMESURF, boxy, boxx, ATTACKINGHLC)
                            
                        # If this is second click
                        elif not firstRightClick:
                            # Save board location
                            newX, newY = boxx, boxy

                            # Now that two clicks have been made, check if move is valid
                            validAction = self.theBoard.isValidAttack(curX, curY, newX, newY)                        

                            # If move is valid make the move
                            if validAction == True:
                                self.makeAttack(curX, curY, newX, newY)
                                self.drawBoard(GAMESURF)
                            else:
                                self.drawBoard(GAMESURF)

            # If it is not my Turn
            elif self.oppTurn == True:
                self.drawBoard(GAMESURF)
                # Displays message "Opponent's move"
                fontObj = pygame.font.Font('freesansbold.ttf', 50)
                textSurfaceObj = fontObj.render("OPPONENT'S TURN....", True, PURPLE, WHITE)
                textSurfaceObj = pygame.transform.rotate(textSurfaceObj, 90)
                textRectObj = textSurfaceObj.get_rect()
                textRectObj.center = (60, 400)
                GAMESURF.blit(textSurfaceObj, textRectObj)
                

            # Get Messages & Update Screen
            self.home.getMessages()
            pygame.display.update()
            FPSCLOCK.tick(FPS)


    # Handles Messages from Opponent during Game
    def handleMsg(self,m):        
        msg = m.split()

        # Confirmation that opponent has set up thier board
        if msg[0] == "BOARDSETUP":
            print("Opponent ready!")
            self.oppReady = True

        # If opponent closed window during game or setup
        if msg[0] == "CLOSED":
            self.gameClosed()

        # Handling resposnses during opponent's turn
        if self.oppTurn == True:
            # If opponent chooses to make a move, update board
            if msg[0] == "MOVE":
                print(self.opponent, " has made a move.")
                self.theBoard.movePiece(msg[1], msg[2], msg[3], msg[4])

            # If opponent chooses to attack a piece of yours
            if msg[0] == "ATTACK":
                print(self.opponent, " is attacking a piece of yours.")
                oppRank = msg[3]
                self.attackingRank = int(oppRank)
                print("The peice attacking you is in row",str(int(msg[1])+1)," and column ",str(int(msg[2])+1)," and has a rank ", oppRank)
                
                # Send back identity of your piece under attack
                myRank = str(self.theBoard.whichPiece(int(msg[4]), int(msg[5])).rank)
                self.myRankAttacked = myRank

                # If your flag has been attacked, game is over
                if myRank == "0":
                    print("OH NO, THEY CAPTURED YOUR FLAG!")
                    sendMessage(self.s, self.opponent, "YOUWON "+myRank)
                    self.myArmy.soldiers[0].status == False
                    self.gettingAttacked(int(oppRank), int(msg[1]), int(msg[2]), int(msg[4]), int(msg[5]))
                    self.endOfGame(self.opponent)

                # If not, return Identity of your piece
                else:
                    sendMessage(self.s, self.opponent, "RANK "+myRank)
                    self.gettingAttacked(int(oppRank), int(msg[1]), int(msg[2]), int(msg[4]), int(msg[5])) 

            
            # If opponent is sending result of an attack
            if msg[0] == "RESULT":
                myRank = str(self.myRankAttacked)
                oppRank = str(self.attackingRank)
                
                # Your piece won this attack
                if msg[1] == myRank:
                    print("Hurray! You prevailed!")

                    # If my piece is movable, move into thier place, overwriting them
                    if (myRank != '0') and (myRank != '-1'):
                        self.theBoard.movePiece(msg[4], msg[5], msg[2], msg[3])

                    # If not movable, just delete them
                    else:
                        self.theBoard.removePiece(msg[2], msg[3])

                # Your piece lost this attack
                elif msg[1] == oppRank:
                    print("Sorry! Your opponent outranked you!")

                    # Remove my piece
                    self.theBoard.removePiece(msg[4], msg[5])

                    # Move their piece into my place
                    if (oppRank != 0) and (oppRank != -1):
                        self.theBoard.movePiece(msg[2], msg[3], msg[4], msg[5])

                # Both pieces lost this attack
                elif msg[1] == "DRAW":
                    print("Lol! You drew against your opponent!")

                    # Remove both our pieces
                    self.theBoard.removePiece(msg[2], msg[3])
                    self.theBoard.removePiece(msg[4], msg[5]) 
            
            # Confirmation that move is over recieved
            if msg[0] == "DONE":
                # Start your turn
                print("Your turn now.")
                self.oppTurn = False
                self.myTurn = True

        # Handling responses during my turn (to my attack)
        elif self.myTurn == True:
            myRank, curX, curY, newX, newY = self.attackInfo
           # If you attacked their Flag
            if msg[0] == "YOUWON":
                print("CONGRATULATIONS YOU CAPTURED YOUR OPPONENT'S FLAG!")
                self.attacking(int(msg[1]), curX, curY, newX, newY)
                self.endOfGame(self.me)

            # If you attacked any other piece
            if msg[0] == "RANK":
                oppRank = int(msg[1])

                self.attacking(oppRank, curX, curY, newX, newY)
                print(" The peice you attacked has a rank ", str(oppRank))

                # Determine the result of this attack
                result = self.theBoard.attackResult(myRank, oppRank)

                # If my piece won
                if result == myRank:
                    print("YOU PREVAILED")

                    # Move into their place, deleting them
                    self.theBoard.movePiece(curX, curY, newX, newY)

                    # Send result of this attack
                    m = "RESULT "+ str(myRank)+" "+str(9-curX)+" "+str(9-curY)+" "+str(9-newX)+" "+str(9-newY)
                    sendMessage(self.s, self.opponent, m)

                # If my piece lost
                elif result == oppRank:
                    print("YOU WERE OUTRANKED")

                    # Remove my piece
                    self.theBoard.removePiece(curX, curY)

                    # Move their piece into my place if it is movable
                    if (oppRank != 0) and (oppRank != -1):
                        self.theBoard.movePiece(newX, newY, curX, curY)

                    # Send result of this attack
                    m = "RESULT "+ str(oppRank)+" "+str(9-curX)+" "+str(9-curY)+" "+str(9-newX)+" "+str(9-newY)
                    sendMessage(self.s, self.opponent, m)

                # If it was a draw
                elif result == "DRAW":
                    print("DRAW")
                    # Remove both pieces
                    self.theBoard.removePiece(curX, curY)
                    self.theBoard.removePiece(newX, newY)

                    # Send result of this attack
                    m = "RESULT "+"DRAW "+str(9-curX)+" "+str(9-curY)+" "+str(9-newX)+" "+str(9-newY)
                    sendMessage(self.s, self.opponent, m)

            
            # Confirm the end of your move
            sendMessage(self.s, self.opponent, "DONE")
            self.attackInfo = (0,0,0,0,0)
            self.myTurn = False
            self.oppTurn = True
           
            
    # Making a Valid Movement
    def makeMove(self, curX, curY, newX, newY):
        # Moving the piece on the board
        self.theBoard.movePiece(curX, curY, newX, newY)
        
        # Send board updates to opponent
        m = "MOVE "+str(9-curX)+" "+str(9-curY)+" "+str(9-newX)+" "+str(9-newY)
        sendMessage(self.s, self.opponent, m)

        # Confirm the end of your move
        sendMessage(self.s, self.opponent, "DONE")    


    # Making a Valid Attack
    def makeAttack(self, curX, curY, newX, newY):

        # Retrieve rank of my attacking piece
        myRank = self.theBoard.whichPiece(curX, curY).rank
        self.attackInfo = (int(myRank), int(curX), int(curY), int(newX), int(newY))
        
        # Request identity of opponent's attacked piece
        m = "ATTACK "+str(9-curX)+" "+str(9-curY)+" "+str(myRank)+" "+str(9-newX)+" "+str(9-newY)
        sendMessage(self.s, self.opponent, m)

    
    # Checking Game Status
    def gameStatus(self):
        # Flag has been removed
        if self.myArmy.soldiers[0].status == False:
            print("You Lost :'(( ")
            # Send Message to opponent that I lost
            self.endOfGame(self.opponent)

        # No movable pieces remain in my army
        remain = False
        for i in self.myArmy.soldiers:
            statusP = i.status
            mobilityP = i.movable
            if statusP == True and  mobilityP == True:
                remain = True

        if remain == False:
            print("You Lost :'(( ")
            # Send Message to opponent that I lost
            self.endOfGame(self.opponent)
    
        # Continue game
        return 1


    # Displays winner and returns to mainloop   
    def endOfGame(self, winner):
        self.gameEnded = True
        fontObj = pygame.font.Font('freesansbold.ttf', 100)
        textSurfaceObj = fontObj.render(winner+" WON!!", True, PURPLE, WHITE)
        textRectObj = textSurfaceObj.get_rect()
        textRectObj.center = (500, 400)
        self.gameDisplay.blit(textSurfaceObj, textRectObj)
        pygame.time.wait(10000)
        if self.opponent in self.home.gamesOpen:
            del self.home.gamesOpen[self.opponent]
        print('THE GAME HAS ENDED.....')
        print('......AND THE WINNER IS .......', winner)

    # When opponent closes thier window
    def gameClosed(self):
        self.gameEnded = True
        fontObj = pygame.font.Font('freesansbold.ttf', 100)
        textSurfaceObj = fontObj.render(self.opponent+" EXITED GAME", True, RED, WHITE)
        textRectObj = textSurfaceObj.get_rect()
        textRectObj.center = (500, 400)
        self.gameDisplay.blit(textSurfaceObj, textRectObj)
        pygame.time.wait(10000)
        if self.opponent in self.home.gamesOpen:
            del self.home.gamesOpen[self.opponent]
        print('THEY LEFT GAME')
  

        
##########  MAIN CODE  ##########

# Creating the Login Screen
def openLoginScreen():
    wnd1 = Tk()
    wnd1.geometry("200x200")
    wnd1.title("Login to STRATEGO")

    firstWindow = loginWnd(wnd1)
    wnd1.mainloop()

    # If login was successful, open Main Screen
    if firstWindow.loginSuccess == True:
        openMainScreen(firstWindow.s, firstWindow.me)


# Creating the Main Screen
def openMainScreen(socket, me):
    wnd2 = Tk()
    wnd2.geometry("600x450")
    wnd2.title("STRATEGO - Home Page for "+me)
    global homeWindow
    homeWindow = userWnd(wnd2, socket, me)
    
    wnd2.mainloop()

# Opening Login Screen
openLoginScreen()

