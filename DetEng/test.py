import tomllib
import sys
import os

# Search in the root directory provided, any/all subsdirectories within it and 
# the files found in those directories (double \\ needed in the path)
for root, dirs, files in os.walk("custom_detections/"):

    # For every file found, check if it has the .toml extension
    # If it is a toml file, load its contents
    for file in files:
        if file.endswith(".toml"):
    
            # Programmatically create the full file path for the TOML files
            # by joining the directory and filename together 
            full_path = os.path.join(root, file)
            print(full_path)
