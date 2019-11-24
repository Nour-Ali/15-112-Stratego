
#    15-112: Principles of Programming and Computer Science
#    Final Project: Implementing an online version of Stratego
#    Name      : Nour Ali
#    AndrewID  : Ntali

## ALL IMPORT STATEMENTS
import socket, time

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
    if response[2] == "ok":
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

########## SERVER COMMUNICATION FUNCTIONS - User Interaction ##########

def ShowUsers(s):
    Users = getUsers(s)
    if Users == []:
        print (">> There are currently no active users")
    else:
        print (">> Active users:")
        for u in Users:
            print ("     " + u)
    
def ShowFriends(s, u):
    Friends = getFriends(s)
    if Friends == []:
        print (">> You currently have no friends")
    else:
        print (">> Your friends:")
        for f in Friends:
            print ("     " + f)
   
def AddFriend(s, u):
    friend = input("Please insert the username of the user you would like to add as a friend: ")
    if sendFriendRequest(s, friend): print (friend, "added succesfully")
    else: print ("Error adding " + friend + ". Please try again.")
    
def AcceptFriend(s, u):
    friend = input("Please insert the username of the user you would like to accept as a friend: ")
    if acceptFriendRequest(s, friend): print ("Request from " + friend + " accepted succesfully")
    else: print ("Error accepting request from " + friend + ". Please try again." )
    
def SendGameReq(s, me):
    friend = input("Please insert the username of the friend you would like to send a Game Request: ")

    # A game request is sent to friend
    if friend in getFriends(s):
        if sendMessage(s, friend, "GAMEREQUEST"):

            # Once the game request is sent, continuosly check for acceptance
            print ("Game Request sent to " + friend + " succesfully")
            response = False
            sent = time.time()
            wait = time.time()

            # Keep checking until acceptance recieved, or end of time limit
            while (response == False) and ((wait-sent)< 180):
                messages = getMail(s)
                for (u,m) in messages:

                    # If acceptance is recieved create a game object
                    if m.split()[0] == "ACCEPTED":
                        response = True
                        print(u, " has accepted your game request!")
                        print("Let's begin:")
                        thisGame = StrategoGame(s, me, me, friend)
                        thisGame.setUpBoard()

                    elif m.split()[0] == "DECLINED":
                        response = True
                        print("Game Request to ", friend," was denied.")
                        
                wait = time.time()

            # If time limit runs out with no acceptance
            # Send a cancellation message
            if response == False:
                print("Sorry! Time ran out. Please send another request.")
                sendMessage(s, friend, "CANCELLED")
                
        else:
            print ("Error sending game request to " + friend + ". Please try again.")
    else:
        print (friend, "is not a Friend. You must add them as a friend before you can send them a game request.")


# Friend Requests    
def GetGameReq(s, me):
 
    messages = getMail(s)
    i = 0
    if messages == []:
        print("You have no game requests currently.")
    else:
        for (u,m) in messages:

            # If Game Request is recieved and not cancelled create a game object
            if (m.split()[0] == "GAMEREQUEST") and ("CANCELLED" not in messages[i:]):

                print("You have a game request from ", u) 
                accept = input(">>   Would you like to accept the request?")

                if accept.lower() == "yes":
                    sendMessage(s, u, "ACCEPTED")
                    print("Let's begin:")
                    thisGame = StrategoGame(s, u, me, u)
                    thisGame.setUpBoard()
                else:
                    print("Maybe next time!")
                    sendMessage(s, u, "DECLINED")

            # If Game Request is recieved and cancelled 
            elif (m.split()[0] == "GAMEREQUEST") and ("CANCELLED" in messages[i:]):
                
                print("Game request from ", u, " cancelled.")
            
            i = i + 1
    

########## GAME LOGIC FUNCTIONS ##########

## GAME PIECE CLASS - Creates a game piece
class gamePiece():
    def __init__(self, name, rank, movable=True, status=True):
        self.name = name
        self.rank = rank
        self.movable = movable
        self.status = status

## ARMY CLASS - Creates an army of game pieces
class army():
    def __init__(self):
        self.soliders = []
        # Add Flag - Rank 0
        self.soliders.append(gamePiece("Flag", 0, False))
        # Add Bombs - Rank -1
        self.soliders = self.soliders + [gamePiece("Bomb", -1, False) for i in range(6)]
        # Add Marshal - Rank 1
        self.soliders.append(gamePiece("Marshal", 1))
        # Add General - Rank 2
        self.soliders.append(gamePiece("General", 2))
        # Add Colonels - Rank 3
        self.soliders = self.soliders + [gamePiece("Colonel", 3) for i in range(2)]
        # Add Major - Rank 4
        self.soliders = self.soliders + [gamePiece("Major", 4) for i in range(3)]
        # Add Captains - Rank 5
        self.soliders = self.soliders + [gamePiece("Captain", 5) for i in range(4)]
        # Add Lieutenants - Rank 6
        self.soliders = self.soliders + [gamePiece("Lieutenant", 6) for i in range(4)]
        # Add Sergeants - Rank 7
        self.soliders = self.soliders + [gamePiece("Sergeant", 7) for i in range(4)]
        # Add Miners - Rank 8
        self.soliders = self.soliders + [gamePiece("Miner", 8) for i in range(5)]
        # Add Scouts - Rank 9
        self.soliders = self.soliders + [gamePiece("Scout", 9) for i in range(8)]
        # Add Spy - Rank 10
        self.soliders.append(gamePiece("Spy", 10))



## GAME BOARD CLASS - Creates & Manages the status of the game board
class gameBoard():
    def __init__ (self):
        self.board = [["-" for i in range(10)] for i in range(10)]

        # Initializes opponents side of the board
        for i in range(4):
            for j in range(10):
                self.board[i][j] = "X"

        # Initializes 'lake' in middle of board
        self.board[4][2] = "O"
        self.board[4][3] = "O"
        self.board[5][2] = "O"
        self.board[5][3] = "O"
        self.board[4][6] = "O"
        self.board[4][7] = "O"
        self.board[5][6] = "O"
        self.board[5][7] = "O"

    # Displays current state of the board
    # Displays name of my soliders, and placeholders for opponents soliders
    def displayBoard(self):
        print("--------------------------------------------------------------------------")
        for i in range(10):
            thisRow = ""
            for j in range(10):
                if type(self.board[i][j]) is str:
                    thisRow = thisRow + self.board[i][j] + "\t"
                else:
                    thisRow = thisRow + str(self.board[i][j].rank) + "\t" #print rank or name?
            
            print(thisRow)
        print("--------------------------------------------------------------------------")

    # Initialize my side of the board
    # Insert each solider into a valid place
    def setUp(self, theArmy):
        self.displayBoard()
        i = 1
        for s in theArmy.soliders:
            print("Piece :", i)
    
            # Until a valid place is found
            placed = False
            while placed == False:
                print(">>  Where would you like to place ", s.name, "of rank", s.rank,' :')
                x = input(">>    Row: ") 
                y = input(">>    Column: ") 

                validInt = "1023456789"
                # Ensure user enters integer:
                if (x in validInt) and (y in validInt):
                    x = int(x)-1
                    y = int(y)-1

                    # Ensure position is within allowed range
                    if (x < 6) or (x > 9) or (y < 0) or (y > 9):
                        print(">>  Out of Range")

                    # Ensure position is not occupied
                    elif not(self.isOccupied(x,y)):
                        placed = True
                        self.board[x][y] = s
                        self.displayBoard()

                    else:
                        print(">>  Position Occupied")
                else:
                    print("You have not entered an valid input!")
                
            i = i + 1

        print("We are done setting up the board!")
        self.displayBoard()


    # Returns object at location x, y
    def whichPiece(self, x, y):
        return self.board[int(x)][int(y)]

    
    # Determines if postion is occupied in board
    def isOccupied(self, x, y):
        if self.board[x][y] == "-":
            return False
        return True

    # Places a game piece into an empty position 
    def movePiece(self,curX, curY, newX, newY):
        self.board[int(newX)][int(newY)] = self.whichPiece(int(curX), int(curY))
        self.board[int(curX)][int(curY)] = "-"

    # Removes a piece from the game board
    def removePiece(self, curX, curY):
        piece = self.whichPiece(int(curX), int(curY))
        if type(piece) is not str:
            piece.status = False
        self.board[int(curX)][int(curY)] = "-"

    # Checks if a possible move is valid
    def isValidMove(self, curX, curY, newX, newY):

        # Check that all positions are within board
        positions = [curX, curY, newX, newY]
        for i in positions:
            if type(i) is not int:
                print("ERROR: You must enter integers!")
                return False
            if (i < 0) or (i > 9):
                print("ERROR: Positions given out of range!")
                return False
            
        # Check that piece is of my army
        piece = self.whichPiece(curX, curY)

        if type(piece) is str:
            print("ERROR: This is not your piece!")
            return False

        # Check that piece is movable
        if piece.movable == False:
            print("ERROR: This piece is not movable!")
            return False

        # Check that new position is unoccupied
        if self.isOccupied(newX, newY) == True:
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
                    if self.isOccupied(i, curY) == True:
                        print("ERROR: Another piece is in the way!")
                        return False

            # MOVING UP
            else:
                for i in range(newX + 1, curX):
                    if self.isOccupied(i, curY) == True:
                        print("ERROR: Another piece is in the way!")
                        return False

        # Obstructions moving horizontally
        if distanceX == 0:
            # Moving RIGHT
            if curY < newY:
                for i in range(curY + 1, newY):
                    if self.isOccupied(curX, i) == True:
                        print("ERROR: Another piece is in the way!")
                        return False

            # MOVING LEFT
            else:
                for i in range(newY + 1, curY):
                    if self.isOccupied(curX, i) == True:
                        print("ERROR: Another piece is in the way!")
                        return False

        print("VALID MOVE")
        return True

    # Checks if a possible attack is valid    
    def isValidAttack(self, curX, curY, newX, newY):

        # Check that all positions are within board
        positions = [curX, curY, newX, newY]
        for i in positions:
            if (i < 0) or (i > 9):
                print("ERROR: Positions given out of range!")
                return False
            
        # Check that attacking piece is of my army
        piece = self.whichPiece(curX, curY)
        if type(piece) is str:
            print("ERROR: This is not your piece!")
            return False

        # Check that attacking piece is movable
        if piece.movable == False:
            print("ERROR: This piece is not movable!")
            return False

        # Check that new position is occupied by opponent
        opp = self.whichPiece(newX, newY)
        if opp != "X":
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

        print("VALID MOVE")
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


##### MAIN GAME CLASS #####
class StrategoGame():
    def __init__(self, s, req, player1, player2):
        self.s = s
        self.reqPlayer = req
        self.me = player1
        self.opponent = player2
        self.myArmy = army()
        self.theBoard = gameBoard()

    # Ensure both playes set up their boards
    def setUpBoard(self):
        print("Let's start setting up the board!")
        self.theBoard.setUp(self.myArmy) 
        sendMessage(self.s, self.opponent, "BOARDSETUP")
        print("Waiting for your opponent to fniish setting up the board ....")
        # Wait for their confirmation
        setup = False
        while setup == False: 
            messages = getMail(self.s)
            for (u,m) in messages:
                 # If confirmation is recieved continue to start game
                if m.split()[0] == "BOARDSETUP":
                    setup = True
                    print(self.opponent, " has finished setting up their board.")
                    print("Let's start the game!")

                    # If I requested the game
                    if self.reqPlayer == self.me:
                        print("You get to make the first move.")
                        self.gameTurn()

                    # If my opponent requested the game
                    elif self.reqPlayer == self.opponent:
                        print(self.opponent, " gets to make the first move.")
                        self.handleOppMove()

    # Handles moves made by the user
    def gameTurn(self):
        # Display the board
        self.theBoard.displayBoard()

        # If the game has not ended
        if self.gameStatus() == 1:

            # Until a valid action has been made
            validAction = False
            while validAction == False:

                # Ask user for choice
                action = input(">>  What action would you like to make on your turn?")

                # User chooses to move a piece
                if action.lower() == "move":
                    curx = input(">>   Move piece at row: ")
                    cury = input(">>   Move piece at column: ")
                    newx = input(">>   Move piece to new row: ")
                    newy = input(">>   Move piece to new column: ")

                    # Ensure moves are all integers
                    validInt = "1023456789"
                    # Ensure user enters integer:
                    if (curx in validInt) and (cury in validInt) and (newx in validInt) and (newy in validInt):
                        curx = int(curx)-1
                        cury = int(cury)-1
                        newx = int(newx)-1
                        newy = int(newy)-1
                    
                        # Check if move is valid
                        validAction = self.theBoard.isValidMove(curx, cury, newx, newy)

                        # If move is valid make the move
                        if validAction == True:
                            self.makeMove(curx, cury, newx, newy)

                    else:
                        print("You have not entered a valid input!")

                # User chooses to attack a piece
                elif action.lower() == "attack":
                    curx = input(">>   My piece at row: ")
                    cury = input(">>   My piece at column: ")
                    newx = input(">>   Attack piece at row: ")
                    newy = input(">>   Attack piece at column: ")

                    # Ensure moves are all integers
                    validInt = "1023456789"
                    # Ensure user enters integer:
                    if (curx in validInt) and (cury in validInt) and (newx in validInt) and (newy in validInt):
                        curx = int(curx)-1
                        cury = int(cury)-1
                        newx = int(newx)-1
                        newy = int(newy)-1

                        # Check if attack is valid
                        validAction = self.theBoard.isValidAttack(curx, cury, newx, newy)

                        # If attack is valid, make the attack
                        if validAction == True:
                            self.makeAttack(curx, cury, newx, newy)

                    else:
                        print("You have not entered a valid input!")

                # If no valid move has been made
                if validAction == False:
                    print("ERROR: This is not a valid action.")

            # Once a valid move is completed, display board and switch turns
            self.theBoard.displayBoard()
            self.handleOppMove()

        # If game has ended:
        else:
            return self.gameEnded(self.opponent)


    # Handling you opponent's turn
    def handleOppMove(self):
        print("Waiting for your opponent to make a move....")

        # Until confirmation that turn is over is recieved
        done = False
        while done == False:
            messages = getMail(self.s)
            for (u,m) in messages:
                r = m.split(' ')

                # If opponent chooses to make a move, update board
                if r[0] == "MOVE":
                    print(self.opponent, " has made a move.")
                    self.theBoard.movePiece(r[1], r[2], r[3], r[4])

                # If opponent chooses to attack a piece of yours
                if r[0] == "ATTACK":
                    print(self.opponent, " is attacking a piece of yours.")
                    oppRank = r[3]
                    print("The peice attacking you is in row",str(int(r[1])+1)," and column ",str(int(r[2])+1)," and has a rank ", oppRank)

                    # Send back identity of your piece under attack
                    myRank = str(self.theBoard.whichPiece(r[4], r[5]).rank)

                    # If your flag has been attacked, game is over
                    if myRank == 0:
                        print("OH NO, THEY CAPTURED YOUR FLAG!")
                        sendMessage(self.s, self.opponent, "YOUWON")
                        self.myArmy.soliders[0].status == False
                        self.gameEnded(self.opponent)

                    # If not, return Identity of your piece
                    else:
                        sendMessage(self.s, self.opponent, "RANK "+myRank)

                # If opponent is sending result of an attack
                if r[0] == "RESULT":

                    # Your piece won this attack
                    if r[1] == myRank:
                        print("Hurray! You prevailed!")

                        # If my piece is movable, move into thier place, overwriting them
                        if (myRank != 0) and (myRank != -1):
                            self.theBoard.movePiece(r[4], r[5], r[2], r[3])

                        # If not movable, just delete them
                        else:
                            self.theBoard.removePiece(r[4], r[5])

                    # Your piece lost this attack
                    elif r[1] == oppRank:
                        print("Sorry! Your opponent outranked you!")

                        # Remove my piece
                        self.theBoard.removePiece(r[4], r[5])

                        # Move their piece into my place
                        if (oppRank != 0) and (oppRank != -1):
                            self.theBoard.movePiece(r[2], r[3], r[4], r[5])

                    # Both pieces lost this attack
                    elif r[1] == "DRAW":
                        print("Lol! You drew against your opponent!")

                        # Remove both our pieces
                        self.theBoard.removePiece(r[2], r[3])
                        self.theBoard.removePiece(r[4], r[5])  

                # Confirmation that move is over recieved
                if r[0] == "DONE":
                    # Exit loop, and start your turn
                    done = True

        self.gameTurn()


    # Making a Valid Movement
    def makeMove(self,curX, curY, newX, newY):
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

        # Request identity of opponent's attacked piece
        m = "ATTACK "+str(9-curX)+" "+str(9-curY)+" "+str(myRank)+" "+str(9-newX)+" "+str(9-newY)
        sendMessage(self.s, self.opponent, m)

        # Await reply with Identity
        response = False
        while response == False:
            messages = getMail(self.s)
            for (u,m) in messages:
                r = m.split(' ')

                # Once a reply is recieved

                # If you attacked their Flag
                if r[0] == "YOUWON":
                    print("CONGRATULATIONS YOU CAPTURED YOUR OPPONENT'S FLAG!")
                    self.gameEnded(self.me)

                # If you attacked any other piece
                if r[0] == "RANK":
                    oppRank = int(r[1])
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
                    response = True


    # Returns Game Status
    def gameStatus(self):
        # Flag has been removed
        if self.myArmy.soliders[0].status == False:
            print("You Lost :'(( ")
            # Send Message to opponent that I lost
            return 0

        # No movable pieces remain in my army
        remain = False
        for i in self.myArmy.soliders:
            statusP = i.status
            mobilityP = i.movable
            if statusP == True and  mobilityP == True:
                remain = True

        if remain == False:
            print("You Lost :'(( ")
            # Send Message to opponent that I lost
            return 0
    
        # Continue game
        return 1


    # Displays winner and returns to mainloop   
    def gameEnded(self, winner):
        print('THE GAME HAS ENDED.....')
        print('......AND THE WINNER IS .......', winner)
        #Display stats
        #Return to main menu
        

########## MAIN CODE ##########

socket = StartConnection("86.36.46.10", 15112)

def PrintUsage(s, u):
    print (">> Menu:")
    print ("     Menu                  Shows a Menu of acceptable commands")
    print ("     Friends               Show your current friends")
    print ("     Add Friend            Send another friend a friend request")
    print ("     Accept Friend         Accept a friend request")
    print ("     Send Game Request     Send a game Request to a friend")
    print ("     Get Game Request      Get all game Requests")
    print ("     Exit                  Exits the chat client")

# Ask the user for their login name and password
username = input(">> Login as: ")
if ("Exit" == username) : exit()

password = input(">> Password: ")
if ("Exit" == password) : exit()

# Run authentication
# Ask for username and password again if incorrect
while not login (socket, username, password):
    print (">> Incorrect Username/Password Combination!")
    print (">> Please try again, or type 'Exit' to close the application.")
    username = input(">> Login as: ")
    if ("Exit" == username) : exit()
    password = input(">> Password: ")
    if ("Exit" == password) : exit()

# Now user is logged in        
# Set up your commands options

menu = {
        "Menu": PrintUsage,
        "Friends": ShowFriends,
        "Add Friend": AddFriend,
        "Accept Friend": AcceptFriend,
        "Send Game Request": SendGameReq,
        "Get Game Request": GetGameReq,
    }

# Prompt the user for a command
print (">> Welcome to The Online World of Stratego, ", username, "!")
print (">> Insert command or type Menu to see a list of possible commands")
prompt = "[" + username + "]>>"
command = input(prompt)

while (command != "Exit"):
    if not command in menu.keys():
        print (">> Unidentified command " + command + ". Please insert valid command or type Menu to see a list of possible commands.")
        prompt = "[" + username + "]>>"
        command = input(prompt)
    else:
        menu[command](socket, username)
        command = input(prompt)                             

