import os

print("hello world")

def list_files_in_current_directory():
    """
    Prints the names of all files in the current working directory.
    """
    print("Listing files in the current directory:")
    try:
        # Get a list of all entries (files and directories) in the current directory
        entries = os.listdir('.')
        
        found_files = []
        # Iterate through the entries and check if each is a file
        for entry in entries:
            if os.path.isfile(entry):
                found_files.append(entry)
        
        if found_files:
            for filename in found_files:
                print(f"- {filename}")
        else:
            print("No files found in the current directory.")

    except OSError as e:
        print(f"Error accessing directory: {e}")

# Call the function to execute the script
if __name__ == "__main__":
    list_files_in_current_directory()

