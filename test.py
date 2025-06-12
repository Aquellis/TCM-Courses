import os

def list_files_in_nested_directories():
    """
    Prints the names of all files found in the current working directory
    and all its subdirectories (nested directories).
    """
    print("Listing files in the current directory and its subdirectories:")
    
    # Counter for files found
    file_count = 0

    try:
        # os.walk() generates the file names in a directory tree
        # by walking the tree either top-down or bottom-up.
        # For each directory in the tree rooted at the topdown argument (default is '.'),
        # it yields a 3-tuple: (dirpath, dirnames, filenames).
        for root, dirs, files in os.walk('DetEng/'):
            for filename in files:
                # Construct the full path to the file
                full_path = os.path.join(root, filename)
                print(f"- {full_path}")
                file_count += 1
        
        if file_count == 0:
            print("No files found in the current directory or its subdirectories.")
        else:
            print(f"\nFound {file_count} file(s) in total.")

    except OSError as e:
        print(f"Error accessing directory: {e}")

# Call the function to execute the script
if __name__ == "__main__":
    list_files_in_nested_directories()

