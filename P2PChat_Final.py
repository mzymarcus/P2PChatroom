#!/usr/bin/python

# Student name and No.: Ma Zhiyu 3035021974
# Student name and No.: Gu Derun 3035140146
# Development platform: Linux (CS lab)
# Python version: 2.7.6
# Version: GCC 4.8.2 


from Tkinter import *
import sys
import socket
import time
import threading

#
# Global variables
#

roomserver = sys.argv[1]
server_port = int(sys.argv[2])
local_port = int(sys.argv[3]) # port number for p2p connection
name = "" # local nickname
roomname = "" # local roomname
hash_id = "" # local hash_id
joined = False # joined a room or not
connected = False # socketUser initialized or not
all_thread_running = True
thread_list = [] # thread list
socketUser = socket.socket() # socket with roomserver
socketUser.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#socketUser.settimeout(1.0)

msg_id = 0 # local hash_id
#msg_id_lock = threading.Lock()

fw_link_list = [] # [(fw_socket, fw_hash_id)]
#fw_link_list_lock = threading.Lock()

bw_list = [] # [(socket, hash_id)]
#bw_list_lock = threading.Lock()

mid_table= [] # [(hash_id, msg_id)]
#mid_table_lock = threading.Lock() 

htable = [] # [(name, ip, port, hash_id)] 
#htable_lock = threading.Lock()
#thread_list = []



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
	global socketUser, roomname, name, fw_link_list, msg_id, hash_id, htable, all_thread_running
	#while(True):
	while all_thread_running:
		print "##### [Thread] Starting Join resend... #####"
		#socketUser_lock.acquire()
		try:
			socketUser.send("J:" + roomname + ":" + name + ":" + socketUser.getsockname()[0] + ":" + str(local_port) + "::\r\n")
			rmsg = socketUser.recv(500)
		except Exception as msg:
			continue
		#socketUser_lock.release()
		#msg_id_lock.acquire()
		update_mid_table(hash_id, msg_id)
		msg_id = msg_id + 1
		#msg_id_lock.release()
		rmsgout = rmsg.split(":")
		index = cal_hid(rmsgout)
		if(fw_link_list == [] or fw_link_list[1] == ""):
			fw_link = socket.socket()
			fw_link.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			fw_link_list.append(fw_link)
			fw_link_list.append("")
		else: 
			existed = False
			for i in htable:
				if(str(i[3]) == str(fw_link_list[1])):
					#print fw_link_list[1]
					existed = True
					#print "existed True"
					break
			if(existed == False):
				fw_link_list[0].close()
				fw_link_list = []
				fw_link = socket.socket()
				fw_link.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				fw_link_list.append(fw_link)
				fw_link_list.append("")
				print "##### Forward link reset #####"
        	if(rmsg.split(":")[0] != "F"):
            		if(fw_link_list[1] == ""):
				#print "find fw!"
				find_fw(rmsg)
        	else:
            		#CmdWin.insert(1.0, "\nResending Error!")
			continue
		for i in range(0,9):
			if(all_thread_running):
				time.sleep(1)
			else:
				print "resend out!"
				return
		
	
def p2p_listening():
	global bw_list, local_port, all_thread_running, thread_list
	listen = socket.socket()
	listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listen.bind(("", local_port))
	listen.listen(5)
	listen.settimeout(1.0)
	print "##### [Thread] Host: ", socket.gethostname()[0], "port: ", local_port, "is open to listen for incoming connection... #####"
	while(all_thread_running):
		print "p2p listening starts!"
		try: 		
			nsocket, add = listen.accept() # establish TCP connection
		except socket.timeout:
			continue	
		message = nsocket.recv(500) # P2P handshake
		if(message != ""):
			bw_list.append((nsocket, sdbm_hash(str(message.split(":")[2]) + str(message.split(":")[3]) + str(message.split(":")[4])))) 
			print "##### Adding to current client backward list: #####"
			print "##### Host: ", nsocket.getsockname()[0], " port #: ", message.split(":")[4], " #####"
			update_mid_table(sdbm_hash(str(message.split(":")[2]) + str(message.split(":")[3]) + str(message.split(":")[4])), str(message.split(":")[5]))
			
			bw_port = threading.Thread(name="backward_thread", target=bwport_thread, args=(nsocket,))
			bw_port.start()
			thread_list.append(bw_port)
	print "p2plisten out!"	
		
def bwport_thread(bwsocket):
	print "##### [Thread] Handling processing for ", bwsocket.getsockname()[0], " port #: ", bwsocket.getsockname()[1], "... #####"
	global msg_id, hash_id, all_thread_running
	#msg_id_lock.acquire()
	update_mid_table(hash_id, msg_id)
	msg_id = msg_id + 1
	bwsocket.send("S:" + str(msg_id) + "::\r\n")
	#msg_id_lock.release()
	while(all_thread_running):
		message = bwsocket.recv(500) # text message
		#print "message"
		if(message != "" and message[0] == "T"):
			#print "message hash value, msgid, midtable", str(message.split(":")[2]), str(message.split(":")[4]), mid_table
			if(message.split(":")[1] == roomname and not(str(message.split(":")[2]), str(message.split(":")[4])) in mid_table):
				update_mid_table(message.split(":")[2], message.split(":")[4])
				send_message(message)
				message = message.split(":")
				for i in range(1, len(message) - 3):
					if(message[i] == ""):
						message[i] = ":"
				MsgWin.insert(1.0, "\n[" + message[3] + "] " + "".join(message[6:(len(message) - 2)])) # + "insert from backward link")
			else:
				#CmdWin.insert(1.0, "\nError for forwarding message!")
				continue
	print "backlistening out!"
	
def update_mid_table(hid, msg_id):
	global mid_table
	#print "hid, msg_id", hid, msg_id
	for i in range(0, len(mid_table)):
		if(str(mid_table[i][0]) == str(hid)):
			del mid_table[i]	
			mid_table.append((str(hid), str(msg_id)))
			return
	mid_table.append((str(hid), str(msg_id)))
	#print "inside the function", mid_table

def send_message(message):
	global fw_link_list, roomname, bw_list
	#print "forward hash not equal message hash", str(fw_link_list[1]) != str(message.split(":")[2])
	#print "fw_link is not null", (fw_link_list[1] != "")
	
	if ((str(fw_link_list[1]) != str(message.split(":")[2])) and (fw_link_list[1] != "")):
		try:		
			fw_link_list[0].send(message)
		except Exception as msg:
			pass
	if (len(bw_list) != 0):	
		for i in (bw_list):
			#print "str i 1 hash value", str(i[1]), "message info hash value", str(message.split(":")[2])
			if(str(i[1]) != str(message.split(":")[2])):
				try:				
					i[0].send(message)
					#print "fageile i[1]"
				except Exception as msg:
					continue
				

def cal_hid(stringout):
	global hash_id, htable
	index1 = -1
	i = 1
	htable = []
	while (i + 2 <= len(stringout) - 1):
		if(stringout[i] != "" and stringout[i+1] != "" and stringout[i+2] != ""):
			tuple1 = (stringout[i], stringout[i+1], stringout[i+2], sdbm_hash(stringout[i] + stringout[i+1] + stringout[i+2]))
			htable.append(tuple1)
			i = i + 3
		else:
			break
	htable.sort(key=lambda tup:tup[3])
	for i in range(0, len(htable)):
		if(htable[i][3] == hash_id):
			index1 = i
			break;	
	return index1

def fw_listen():
	print "[Thread] Listening to the forwarding link... #####"
	global fw_link_list, mid_table, all_thread_running
	while(all_thread_running):
		message = fw_link_list[0].recv(500)
		#print "message fw:", message
		if(message != "" and message[0] == "T"):
			messageout = message.split(":")
			print "fw info hash, msg_id, midtable", str(messageout[2]), str(messageout[4]), mid_table
			if(not(str(messageout[2]), str(messageout[4])) in mid_table):
				MsgWin.insert(1.0, "\n[" + messageout[3] + "] " + "".join(messageout[6:(len(messageout) - 2)])) # + "insert from forward link")
				update_mid_table(messageout[2], messageout[4])
				send_message(message)

	print "fw_listen out!"

def find_fw(rmsg):
	global msg_id, htable, hash_id, bw_list, roomname, socketUser, fw_link_list, name, fw_link_list, thread_list
	index = -1	
	for i in range(0, len(htable) - 1):
		if(htable[i][3] == hash_id):
			index = i	
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
			if(fw_link_list[1] == ""):
				fw_link_list[0].connect((htable[connect_index][1], int(htable[connect_index][2])))
				print "##### Forward link host: ", fw_link_list[0].getpeername()[0], " port #: ", fw_link_list[0].getpeername()[1], " #####"
				fw_link_list[1] = htable[connect_index][3]
			fw_link_list[0].send("P:" + roomname + ":" + name + ":" + str(socketUser.getsockname()[0]) + ":" + str(sys.argv[3]) + ":" + str(msg_id) + "::\r\n")
			update_mid_table(hash_id, msg_id)
			msg_id = msg_id + 1		
			fw_listening = threading.Thread(name = "fw_listen", target = fw_listen)
			fw_listening.start()
			thread_list.append(fw_listening)
	else:	
		print "##### Backward_list is empty #####"
		if(htable[connect_index][3] != hash_id):
			if(fw_link_list[1] == ""):
				fw_link_list[0].connect((htable[connect_index][1], int(htable[connect_index][2])))
				print "##### Forward link host: ", fw_link_list[0].getpeername()[0], " port #: ", fw_link_list[0].getpeername()[1], " #####"
				fw_link_list[1] = htable[connect_index][3]
			fw_link_list[0].send("P:" + roomname + ":" + name + ":" + str(socketUser.getsockname()[0]) + ":" + str(local_port) + ":" + str(msg_id) + "::\r\n")
			update_mid_table(hash_id, msg_id)				
			msg_id = msg_id + 1			
			fw_listening = threading.Thread(name = "fw_listen", target = fw_listen)
			fw_listening.start()
			thread_list.append(fw_listening)

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
	global connected, socketUser, hash_id, msg_id
	if not connected:
		socketUser.connect((roomserver, server_port))
		connected = True
	socketUser.send("L::\r\n")
	rmsg = socketUser.recv(500)
	update_mid_table(hash_id, msg_id)
	msg_id = msg_id + 1
	rmsg = rmsg.split(":")
	if(rmsg[0] == "F"):
		CmdWin.insert("Error for getting the member list!")
		return 
	else:	
		if(rmsg[1] != "" and rmsg[1] != " "):
			CmdWin.insert(1.0, "\n            [Room] " + "\n            [Room] ".join(rmsg[1:(len(rmsg)-2)]))
		CmdWin.insert(1.0, "\nHere are the active chatrooms:")

def do_Join():
	print "##### Join buttion pressed #####"
	global joined, roomname, name, connected, roomserver, server_port, local_port, socketUser, hash_id, htable, msg_id, thread_list
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
			connected = True 
        	hash_id = sdbm_hash(name + str(socketUser.getsockname()[0]) + str(local_port))
		socketUser.send("J:" + roomname + ":" + name + ":" + socketUser.getsockname()[0] + ":" + str(local_port) + "::\r\n") 
		#print "hash_id", hash_id, name, str(socketUser.getsockname()[0]), str(local_port)
		rmsg = socketUser.recv(500)
		#msg_id_lock.acquire()
		update_mid_table(hash_id, msg_id)
		msg_id = msg_id + 1
		#msg_id_lock.release()
		rmsgout = rmsg.split(":")
		if(rmsgout[0] == "F"):
			CmdWin.insert("Error for joining the chatroom!")
			return
		else:	
			joined = True	
			if(rmsg[0] != "" and rmsg[0] != " "):
				CmdWin.insert(1.0, "\n          [Member]" + rmsg)
			CmdWin.insert(1.0, "\nHere are the active members of that chatroom!")
			
			resend = threading.Thread(name="Resendthread", target=resend_thd)
			resend.start();
			thread_list.append(resend)

			listen_thread = threading.Thread(name="P2PListening", target=p2p_listening)
			listen_thread.start()
			thread_list.append(listen_thread)

def do_Send():
	print("##### Send button pressed #####")
	global joined, msg_id, roomname, hash_id, name
	text = userentry.get()
	if(text == ""):
		CmdWin.insert(1.0, "\nPlease fill the content window!")
		return
	elif(not joined):
		CmdWin.insert(1.0, "\nPlease join a chatroom first!")
	else:	
		raw_text = text	
		#msg_id_lock.acquire()
		text = "T:" + roomname + ":" + str(hash_id) + ":" + name + ":" + str(msg_id) + ":" + str(len(text)) + ":" + text + "::\r\n"
		#msg_id_lock.release()
 		
		#msg_id_lock.acquire()
		update_mid_table(hash_id, msg_id)		
		msg_id = msg_id + 1	
		send_message(text)
		#msg_id_lock.release()
		MsgWin.insert(1.0, "\n[" + name + "] " + raw_text) # + "self-insert");
		userentry.delete(0, END)
		

def do_Quit():
	global socketUser, bw_list, fw_link_list, thread_list, all_thread_running, thread_list
	all_thread_running = False
	socketUser.close()
	for i in bw_list:
		i[0].close()
	if(len(fw_link_list) != 0):
		fw_link_list[0].close()
	for i in thread_list:
		i.join()
	#win.destroy()
	sys.exit(0)
	
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

