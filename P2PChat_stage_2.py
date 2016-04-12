#!/usr/bin/python

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from Tkinter import *
import sys
import socket
import time
import threading

#
# Global variables
#

name = "" # local nickname
roomname = "" # local roomname
hash_id = "" # local hash_id
msg_id = 0 # local hash_id
joined = False # joined a room or not
connected = False # socketUser initialized or not
fw_hash_id = "" # fowarding link hash_id
roomserver = sys.argv[1]
server_port = int(sys.argv[2])
local_port = int(sys.argv[3]) # port number for p2p connection
socketUser = socket.socket() # socket with roomserver
socketUser.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
fw_link = socket.socket() # socket with forward link
fw_link.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bw_list = [] # [(socket, hash_id)]
bw_table= [] # [(hash_id, msg_id)] 
htable = [] # [(name, ip, port, hash_id)]

#thread_list = []
#lock = threading.Lock()

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0L
	for c in instr:
		hash = long(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def resend_thd():
	global socketUser, roomname, name, fw_hash_id
	while(True):
		print "##### [Thread] Starting Join resend... #####"
		socketUser.send("J:" + roomname + ":" + name + ":" + socketUser.getsockname()[0] + ":" + str(local_port) + "::\r\n")
		rmsg = socketUser.recv(500)
        	if(rmsg.split(":")[0] != "F"):		
            		if(fw_hash_id == ""):
				find_fw(rmsg)
        	else:
            		CmdWin.insert(1.0, "\nResending Error!")
		print "##### [Thread] Join resend process stops... #####"
		time.sleep(20)

def p2p_listening():
	global bw_list, local_port 
	listen = socket.socket()
	listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listen.bind(("", local_port))
	listen.listen(5)
	print "##### [Thread] Host: ", socket.gethostname()[0], "port: ", local_port, "is open to listen for incoming connection... #####"
	while(True):
		"##### Port #: ", local_port, " is listening #####"
		nsocket, add = listen.accept() # establish TCP connection
		print "##### TCP connection established with host: ", add[0], " port #: ", add[1], " #####"		
		message = nsocket.recv(500) # P2P handshake
		print "##### P2P handshake accomplished #####"
		bw_list.append((nsocket, sdbm_hash(str(message.split(":")[2]) + str(message.split(":")[3]) + str(message.split(":")[4])))) 
		print "##### Adding to current client backward list: #####"
		print ("##### Host: ", nsocket.getsockname()[0], " port #: ", message.split(":")[3], " #####")
		update_bw_table(sdbm_hash(str(message.split(":")[2]) + str(message.split(":")[3]) + str(message.split(":")[4])), str(message.split(":")[5]))
		print "##### Updating backward table for ", nsocket.getsockname()[0], " #####"
		bw_port = threading.Thread(name="backward_thread", target=bwport_thread, args=(nsocket,))
		bw_port.start()
		#thread_list.append(bw_port)

def bwport_thread(bwsocket):
	print "##### [Thread] Handling processing for ", bwsocket.getsockname()[0], " port #: ", bwsocket.getsockname()[1], "... #####"
	global msg_id, bw_table, hash_id
	bwsocket.send("S:" + str(msg_id) + "::\r\n")
	print "##### Sending back response for P2P handshake #####"
	update_bw_table(hash_id, msg_id)
	msg_id = msg_id + 1
	while(True):
		print "##### Listening to ", bwsocket.getsockname()[0], " port #: ", bwsocket.getsockname()[1], " #####"
		message = bwsocket.recv(500) # text message
		print "##### Message received from ", bwsocket.getsockname()[0], " port #: ", bwsocket.getsockname()[1], " #####"
		if(message.split(":")[1] == roomname and not(message.split(":")[2], message.split(":")[4]) in bw_table):
			print "##### Forward to other peers #####"
			send_message(message)
			print "##### Updating the backward table #####"
			update_bw_table(message.split(":")[2], message.split(":")[4])
			message = message.split(":")
			for i in range(1, len(message) - 3):
				if(message[i] == ""):
					message[i] = ":"
			print "##### Print out message #####"
			MsgWin.insert(1.0, "\n[" + message[3] + "] " + "".join(message[6:(len(message) - 2)]))
			MsgWin.insert(1.0, "1")
		else:
			CmdWin.insert(1.0, "\nError for forwarding message!")

def update_bw_table(hid, msg_id):
	print "##### Update backward_table #####"
	global bw_table
	#lock.acquire()
	for i in (bw_table):
		if(i[0] == hid):
			i = (hid, msg_id)
			return
	bw_table.append((hid, msg_id))
	print "##### Backward table updating finishes #####"

def send_message(message):
	print "##### Sending message #####"
	global fw_link, fw_hash_id, roomname, bw_list
	if ((str(fw_hash_id) != str(message.split(":")[2])) and (fw_hash_id != "")):
		fw_link.send(message)
		print "##### Sent to forward link #####"
	if (len(bw_list) != 0):	
		print "##### Trying to send to backward links #####"
		for i in (bw_list):		
			if(str(i[1]) != str(message.split(":")[2])):		
				i[0].send(message)
				print "##### sent to host: ", i[0].getsockname()[0], " port #: ", i[0].getsockname()[1], " #####"

def cal_hid(stringout):
	print "##### Calculating the Hash table for all the members in the group #####"
	global hash_id, htable
	index1 = -1
	i = 1
	while (i <= len(stringout) - 1):
		if(stringout[i] != "" and stringout[i+1] != "" and stringout[i+2] != ""):
			tuple1 = (stringout[i], stringout[i+1], stringout[i+2], sdbm_hash(stringout[i] + stringout[i+1] + stringout[i+2]))
			if(not (tuple1 in htable)):
				htable.append(tuple1)
				print "##### Updating the Hash table with tuple ", tuple1, " #####"
			i = i + 3
		else:
			break
	htable.sort(key=lambda tup:tup[3])
	for i in range(0, len(htable)):
		if(htable[i][3] == hash_id):
			index1 = i
			break;	
	print "##### The index for current client is: ", index1, " #####"
	return index1

def fw_listen():
	print "[Thread] Listening to the forwarding link... #####"
	global fw_link, bw_table
	while(True):
		message = fw_link.recv(500)
		print "##### Message received from forward link #####"
		message = message.split(":")
		if(not(message[2], message[4]) in bw_table):
			MsgWin.insert(1.0, "\n[" + message[3] + "] " + "".join(message[6:(len(message) - 2)]))
			MsgWin.insert(1.0, "2")
			update_bw_table(message[2], message[4])
			print "##### Backward table updated #####"
		#lock.release()

def find_fw(rmsg):
	print "##### Finding the forward link for current client #####"
	global msg_id, htable, hash_id, bw_list, roomname, socketUser, fw_hash_id, name, fw_link
	rmsgout = rmsg.split(":")
	index = cal_hid(rmsgout)
	connect_index = (index + 1) % (len(htable));
	if(connect_index == index):
		return
	if(bw_list != []):
		print "##### Backward_list is not empty #####"
		found = False
		while(htable[connect_index][3] != hash_id):
			for i in bw_list:
				if(i[1] == htable[connect_index][3]):
					found = True
					break
	 		if(found == False):
				break
			else:
				connect_index = (connect_index + 1) % len(htable)
		if(found == False):
			if(fw_hash_id == ""):
				print "##### Establishing TCP connection with forward link #####"
				fw_link.connect((htable[connect_index][1], int(htable[connect_index][2])))
				print "##### Forward link host: ", fw_link.getpeername()[0], " port #: ", fw_link.getpeername()[1], " #####"
			fw_link.send("P:" + roomname + ":" + name + ":" + str(socketUser.getsockname()[0]) + ":" + str(sys.argv[3]) + ":" + str(msg_id) + "::\r\n")
			print "##### P2P handshake application sent #####"
			if(fw_link.recv(500).split(":")[0] == "S"):
				fw_hash_id = htable[connect_index][3]
				print "##### Forward link hash id updated #####"
			update_bw_table(hash_id, msg_id)
			msg_id = msg_id + 1			
			fw_listening = threading.Thread(name = "fw_listen", target = fw_listen)
			fw_listening.start()
	else:	
		print "##### Backward_list is empty #####"
		if(htable[connect_index][3] != hash_id):
			if(fw_hash_id == ""):
				print "##### Establishing TCP connection with forward link #####"
				fw_link.connect((htable[connect_index][1], int(htable[connect_index][2])))
				print "##### Forward link host: ", fw_link.getpeername()[0], " port #: ", fw_link.getpeername()[1], " #####"
			fw_link.send("P:" + roomname + ":" + name + ":" + str(socketUser.getsockname()[0]) + ":" + str(local_port) + ":" + str(msg_id) + "::\r\n")
			print "##### P2P handshake application sent #####"
			if(fw_link.recv(500).split(":")[0] == "S"):
				fw_hash_id = htable[connect_index][3] 
				print "##### Forward link hash id updated #####"
			update_bw_table(hash_id, msg_id)				
			msg_id = msg_id + 1				
			fw_listening = threading.Thread(name = "fw_listen", target = fw_listen)
			fw_listening.start()

def do_User():
	print "##### User buttion pressed #####"
	global name, joined
	outstr = "\n[User] username: "+userentry.get()
	if userentry.get() == "":
		CmdWin.insert(1.0, "\nUsername cannot be null, please check!")
	elif (name != ""):
		CmdWin.insert(1.0, "\nYou have already set a name!")
	elif joined: 
		CmdWin.insert(1.0, "\nYou have already joined one chat room, and you cannot change your nickname!")
	else:
		name = userentry.get()		
		CmdWin.insert(1.0, outstr)
		userentry.delete(0, END)

def do_List():
	print "##### List button pressed #####"
	global connected, socketUser
	if not connected:
		socketUser.connect((roomserver, server_port))
		connected = True
		print "##### Established TCP connection with roomserver #####"
	socketUser.send("L::\r\n")
	rmsg = socketUser.recv(500)
	rmsg = rmsg.split(":")
	if(rmsg[0] == "F"):
		CmdWin.insert("Error for getting the member list!")
		return 
	else:
		CmdWin.insert(1.0, "\n" + "; ".join(rmsg[1:(len(rmsg)-2)]))
		CmdWin.insert(1.0, "\nHere are the active chatrooms:")

def do_Join():
	print "##### Join buttion pressed #####"
	global joined, roomname, name, connected, roomserver, server_port, local_port, msg_id, socketUser, hash_id, fw_link, htable
	roomname = userentry.get()
	if joined:
		CmdWin.insert(1.0, "\nYou have already joined one chat room, cannot join again!")
	elif roomname == "":
		CmdWin.insert(1.0, "\nPlease type a roomname you want to join!")
	elif name == "":
		CmdWin.insert(1.0, "\nPlease register for an username first!")
	else:	
		if not connected:
			socketUser.connect((roomserver, server_port))
			connected = True ### exception handling
			print "##### Established TCP connection with roomserver #####"
        
		hash_id = sdbm_hash(name + str(socketUser.getsockname()[0]) + str(local_port))
		socketUser.send("J:" + roomname + ":" + name + ":" + socketUser.getsockname()[0] + ":" + str(local_port) + "::\r\n") 
		print "##### Join message sent #####"
		rmsg = socketUser.recv(500)
		print "##### Join feedback received #####"
		rmsgout = rmsg.split(":")
		if(rmsgout[0] == "F"):
			CmdWin.insert("Error for joining the chatroom!")
			return
		else:	
			joined = True	
			CmdWin.insert(1.0, "\n" + rmsg)
			CmdWin.insert(1.0, "\nHere are the active members of that chatroom!")
			
			resend = threading.Thread(name="Resendthr1ead", target=resend_thd)
			resend.start();
			#thread_list.append(resend)

			listen_thread = threading.Thread(name="P2PListening", target=p2p_listening)
			listen_thread.start()
			#thread_list.append(listen_thread) !!!!!!!!!!!!!!!
			
			find_fw(rmsg)

def do_Send():
	print("##### Send button pressed #####")
	global joined, msg_id, roomname, hash_id, name, fw_link
	text = userentry.get()
	if(text == ""):
		CmdWin.insert(1.0, "\nPlease fill the content window!")
		return
	elif(not joined):
		CmdWin.insert(1.0, "\nPlease join a chatroom first!")
	else:	
		raw_text = text		
		text = "T:" + roomname + ":" + str(hash_id) + ":" + name + ":" + str(msg_id) + ":" + str(len(text)) + ":" + text + "::\r\n"
 		send_message(text)
		update_bw_table(hash_id, msg_id)		
		msg_id = msg_id + 1		
		MsgWin.insert(1.0, "\n[" + name + "] " + raw_text);
		MsgWin.insert(1.0, "3")
		userentry.delete(0, END)
		

def do_Quit():
	'''global socketUser, fw_link, bw_list, thread_list
	for i in thread_list:
		i.join()
	socketUser.close()
	fw_link.close()
	for i in range(0, len(bw_list)):
		bw_list[i].close()
	CmdWin.insert(1.0, "\nPress Quit")
	sys.exit(0)
    '''
#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print "P2PChat.py <server address> <server port no.> <my port no.>"
		sys.exit(2)

	win.mainloop()

if __name__ == "__main__":
	main()

