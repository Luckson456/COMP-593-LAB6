import requests
import hashlib
import os
import subprocess
def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    url="https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.7z.sha256" # url from d2l link to get sha file 
    resp_msg=requests.get(url)  #it will send a get request text to extract the downloaded file
    
    if resp_msg.status_code== requests.codes.ok:  #check whether the download is successful or not
        file_content= resp_msg.text # extract text file from resp msg
        
        lines=file_content.split('\n')
        #split text contents into lines
        
        for line in lines:
            if 'vlc-3.0.17.4-win64.exe' in line:
                parts=line.split()
                return parts[0]
    
    # Hint: See example code in lab instructions entitled "Extracting Text from a Response Message Body"
    # Hint: Use str class methods, str slicing, and/or regex to extract the expected SHA-256 value from the text 
    return  None

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # TODO: Step 2
    url="https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.7z.sha256"
    resp_msg=requests.get(url)
    
    if resp_msg.status_code==requests.codes.ok:
        return resp_msg.content
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    return None

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expected SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
    hash_value=hashlib.sha256(installer_data).hexdigest()
    

    # Hint: See example code in lab instructions entitled "Computing the Hash Value of a Response Message Body"
    return hash_value==expected_sha256

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    dir_path=os.path.join(r"C:\Users\lucks\OneDrive\Pictures\COMP-593-LAB6")
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    with open(dir_path,'wb') as  file:
        file.write(installer_data)
    
    return dir_path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    subprocess.run([installer_path,'/L=1033','/S'],check=True)
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    
def delete_installer(installer_path):
    # TODO: Step 6
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    os.remove(installer_path)


if __name__ == '__main__':
    main()