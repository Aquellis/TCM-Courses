# This script attempts to crack a user-defined SHA256 hash against the rockyou wordlist
# Logic is taken from the TCM Python 101 for Hackers course: https://academy.tcm-sec.com/p/python-101-for-hackers 

from pwn import *
import sys

# Accept user input for the hash to crack
if len(sys.argv) != 2:
	print("Please enter the hash you wish to crack.")
	print("Example usage: python3 {} <hash>".format(sys.argv[0]))
	sys.exit()

# Assign the hash from user input
userHash = sys.argv[1]

passwordlist = "/usr/share/wordlists/rockyou.txt"
attempts = 0 # Counter for the number of cracking attempts performed

# Use pwntools log.progress to update us on the job status
with log.progress("Attempting to crack: {} \n".format(userHash)) as cracker:
	# Open the rockyou wordlist file, specfiying the file encoding to read all listed passwords
	with open(passwordlist, "r", encoding='latin-1') as wordlist:
		for password in wordlist:
			password = password.strip("\n").encode('latin-1') # Remove the newline character from each line

			# Calculate the SHA256 hash for the password read from rockyou wordlist
			password_hash = sha256sumhex(password)

			# Print the current status of the cracking job
			cracker.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))

			# If the matching password hash is found, print the associated password and exit the script
			if password_hash == userHash:
				cracker.success("Password hash cracked after {} attempts! Your hash {} is the password: {}".format(attempts, password_hash, password.decode('latin-1')))
				exit()

			attempts += 1 # Increase the count of attempts performed

		# If a matching password hash is not found, print a failure message
		cracker.failure("Password hash not found!")

wordlist.close()