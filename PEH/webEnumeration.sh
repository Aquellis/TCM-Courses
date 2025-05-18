#!/bin/bash

#This script was developed following the Practical Ethical Hacking course material
#provided by TCM Security: https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course

#URL variable is the first argument when running the script
domain=$1

#A new directory needs to be created to save assetfinder output
#Check if both the autoWebRecon and nested folder w/ URL exist, if not then create them
if [ ! -d "autoWebRecon" ];then
	mkdir autoWebRecon
fi

if [ ! -d "autoWebRecon/$domain" ];then
	mkdir autoWebRecon/$domain
fi

#Run assetfinder with our domain argument and save the output in a new directory
echo "~~~Now harvesting subdomains with assetfinder~~~"
assetfinder --subs-only $domain >> autoWebRecon/$domain/af_subdomains.txt

#Run amass with our domain argument and save the output in the same directory
echo "~~~Now harvesting subdomains with owasp-amass~~~"
amass enum -d $domain >> autoWebRecon/$domain/amass_subdomains.txt

#Remove duplicate subdomains using sort -u
sort -u autoWebRecon/$domain/amass_subdomains.txt >> autoWebRecon/$domain/amass_sorted_subdomains.txt

#Take the output files from the previous tools and place all discovered subdomains in one list
cat autoWebRecon/$domain/af_subdomains.txt >> autoWebRecon/$domain/full_subdomain_list.txt
cat autoWebRecon/$domain/amass_sorted_subdomains.txt >> autoWebRecon/$domain/full_subdomain_list.txt

#Run httprobe against the full list of discovered subdomains to determine which ones are alive
#Again remove duplicates with sort -u
#Saves list of alive domains in a separate output file
echo "~~~Now probing subdomains to find which are alive~~~"
cat autoWebRecon/$domain/full_subdomain_list.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> autoWebRecon/$domain/alive_subdomains.txt
