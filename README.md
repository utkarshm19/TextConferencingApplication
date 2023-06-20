# TextConferencingApplication
Text Conferencing Application that uses Client-Server paradigm in C using socket programming. Users can create meeting rooms and chat with each other. Additional features include user registration, inactivity timer.

Feature One: User registration
To implement User Registration the following needed to be completed:
1) Add persistent storage for the username and password
2) Modify the server login logic to check with the persistent storage
3) Create a registration process

We will discuss these in more detail below.
1) Adding Persistent Storage
The persistent storage took the form of a text file, "users.txt",
because a file is persistent on the computer and the implmentation is simple.
Each (username, password) account is stored as a row in the text file.
The format of the row is "username,password", i.e., 
the username and password is comma separated.

2) Modify Server Login Logic
By using "users.txt" to keep track of all accounts, the login process
(in func handle_login) must change to check the "users.txt" each time.
Instead of reading from the file directly, a function called 
get_all_username_and_passwords() reads the file data and converts it to
a C array of `struct userpwd`, which contains the usernames and passwords
of all accounts.

3) Registration Process
On the client side, we add a command "/register" which is of similar format to
the "/login" command. Taking in the username, password, ip, and port.
We add a new message type: "REGISTER" to handle this command on the server.
The server checks if the username and password are valid
(does not contain commas, has not previously been regiestered) and
sends an acknowledgement back.

Feature Two: Inactivity timer
To implement timeout that logs out users that have been inactive for "INACTIVITY_TO" seconds,
the following needed to be completed:
1) Store the last active time of each client
2) Implement the logic for when to time the user out
3) Modify the synchronous blocking function
4) Add a logout acknowledgement

1) Store last active time
On the server, we add the field "time_t last_active_time" to the "struct client".
This is so we can store the last active time for each client.

2) Logic for when to timeout user
On the server, anytime the "poll" function unblocks, we go through each client 
to check if any client has been inactive for "INACTIVITY_TO" seconds.
We use the "last_active_time" implemented in part 1.

3) Modify synchronous blocking (poll function)
Since the poll function only unblocks when there is activit from any client,
to handle the case where all clients are inactive, we have to add
a timeout for the poll function itself.
The timeout value is determined by looking at the client who is closest to
timing out.

4) Adding a logout ACK
The server must notify the client that it has been logged out.
So, a "LOGOUT" message type was added.
