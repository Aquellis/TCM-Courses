#!/bin/bash

# This script was developed following the Practical Ethical Hacking course material
# provided by TCM Security: https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course
# then edited using course material from https://academy.tcm-sec.com/p/osint-fundamentals

# The purpose of this script is to automate the task of performing website OSINT utilizing
# tools like WHOIS, assetfinder, subfinder and gowitness

# Domain variable is the first argument when running the script
domain=$1

# Define colors for terminal output
RED="\033[1;31m" # Print text in red
RESET="\033[0m"  # Remove the red color

# Assign path variables
basePath="autoWebRecon"         # Base directory for all web OSINT
domPath="$basePath/$domain"     # Directory for individual domains
ssPath="$domPath/screenshots"   # Directory for domain screenshots

# Check if these directories exist and create them if not
# (do not throw an error if the paths already exist)
for path in "$basePath" "$domPath" "$ssPath"; do
        if [ ! -d "$path" ]; then
                mkdir -p "$path"
        fi
done

# Perform a WHOIS query on the given domain argument and save the output in a file
echo -e "${RED} ~~~Now querying WHOIS~~~ ${RESET}"
whois "$domain" > "$domPath/whois.txt"

# Run assetfinder on the given domain argument and save the output in a file
echo -e "${RED} ~~~Now harvesting subdomains with assetfinder~~~ ${RESET}"
assetfinder --subs-only $domain >> "$domPath/af_subdomains.txt"

# Run subfinder on the given domain argument and save the output in a file
echo -e "${RED} ~~~Now harvesting subdomains with subfinder~~~ ${RESET}"
subfinder -d "$domain" > "$domPath/sf_subdomains.txt"

# Take the output files from the previous tools and place all discovered subdomains in one list
cat "$domPath/af_subdomains.txt" >> "$domPath/full_subdomain_list.txt"
cat "$domPath/sf_subdomains.txt" >> "$domPath/full_subdomain_list.txt"

# Run httprobe against the full list of discovered subdomains to determine which ones are alive
# Again remove duplicates with sort -u
# Saves list of alive domains in a separate output file
echo -e "${RED} ~~~Now probing subdomains to find which are alive~~~ ${RESET}"
cat "$domPath/full_subdomain_list.txt" | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> "$domPath/alive_subdomains.txt"

# Run gowitness on the alive subsomains and save the screenshots in a separate nested folder
echo -e "${RED} ~~~Now taking screenshots of all the alive subdomains~~~ ${RESET}"
gowitness scan file -f "$domPath/alive_subdomains.txt" -s "$ssPath/" --no-http
