import hashlib
import os
import requests
from tkinter import *
from tkinter import messagebox, filedialog
import threading

# MD5 hash signature library of known viruses
virus_signatures = {
    'eda588c0ee78b585f645aa42eff1e57a': 'Prank Program: Trojan.Win32.FormatAll.V',
    '19dbec50735b5f2a72d4199c4e184960': 'Virus: Trojan.Win32.MEMZ.A',
    '815b63b8bc28ae052029f8cbdd7098ce': 'Prank Program: Virus.Win32.Blamon',
    'c71091507f731c203b6c93bc91adedb6': 'Unknown Virus 1',
    '0a456ffff1d3fd522457c187ebcf41e4': 'Unknown Virus 2',
    '1aa4c64363b68622c9426ce96c4186f2': 'Unknown Virus 3',
    'd214c717a357fe3a455610b197c390aa': 'Unknown Virus 4',
    'b14299fd4d1cbfb4cc7486d978398214': 'Unknown Virus 5',
    'dffe6e34209cb19ebe720c457a06edd6': 'Unknown Virus 6',
    '512301c535c88255c9a252fdf70b7a03': 'Unknown Virus 7',
    'd4a05ada747a970bff6e8c2c59c9b5cd': 'Unknown Virus 8',
    'ad41ec81ab55c17397d3d6039752b0fd': 'Unknown Virus 9',
    'a57db79f11a8c58d27f706bc1fe94e25': 'Unknown Virus 10',
    'fc14eaf932b76c51ebf490105ba843eb': 'Unknown Virus 11',
    '2a92da4b5a353ca41de980a49b329e7d': 'Unknown Virus 12',
    '68abd642c33f3d62b7f0f92e20b266aa': 'Unknown Virus 13',
    'ff5e1f27193ce51eec318714ef038bef': 'Unknown Virus 14',
    '4c36884f0644946344fa847756f4a04': 'Unknown Virus 15',
    '2391109c40ccb0f982b86af86cfbc900': 'Unknown Virus 16',
    '915178156c8caa25b548484c97dd19c1': 'Unknown Virus 17',
    'dac5f1e894b500e6e467ae5d43b7ae3e': 'Unknown Virus 18',
    '84c82835a5d21bbcf75a61706d8ab549': 'Unknown Virus 19',
    'db349b97c37d22f5ea1d1841e3c89eb4': 'Unknown Virus 20',
    '1de73f49db23cf5cc6e06f47767f7fda': 'Unknown Virus 21',
    '71b6a493388e7d0b40c83ce903bc6b04': 'Unknown Virus 22',
    'b1a85fdd944c21070a0551e8c59a6158': 'Unknown Virus 23',
    'e60e767e33acf49c02568a79d9cbdadd': 'Unknown Virus 24',
    'f5ecda7dd8bb1c514f93c09cea8ae00d': 'Unknown Virus 25',
    '6cdcb9f86972efc4cfce4b06b6be053a': 'Unknown Virus 26',
    'f785b1a9a657aca7e70d16ac5effaabd': 'Unknown Virus 27',
    'ebcdda10fdfaa38e417d25977546df4f': 'Unknown Virus 28',
    'e22638ce44a5f9faf9dd450438c1d492': 'Unknown Virus 29',
    'de35f0262c089cc880fe8cee5d6b0156': 'Unknown Virus 30',
    'a635d6a35c2fc054042b6868ef52a0c3': 'Unknown Virus 31',
    'c4391b3b073bb1354afef0f1260b8fb8': 'Unknown Virus 32',
    'cd8c86863628f4d0c7f54fc3350fb1d9': 'Unknown Virus 33',
    'af6d91121887f5bb0a85a06b1ded0db7': 'Unknown Virus 34',
    '29b1550a1de57efda52b039aedeb4710': 'Backdoor Virus 1',
    '203c4f24052a8df191e7c9fdc74a3b38': 'Backdoor Virus 2',
    '7d8dcebef26d40a717a1dbdf895c8676': 'Backdoor Virus 3',
    'b9b5ce28fab628f9e15a4fddc031e902': 'exercise'
}

# Simple list of malicious strings (for string matching)
malicious_strings = [
    "malware",
    "virus",
    "trojan",
    "ransomware",
    "exploit",
    # Other suspicious strings...
]

# VirusTotal API key
API_KEY = 'dc1af1bd484306c9c114e929a3c96a9e8b99fa22851da0dfc4a57b8378116a3e'


def calculate_md5(file_path):
    """Calculate the MD5 hash of a file"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def analyze_file_content(file_path):
    """Analyze file content for suspicious strings"""
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
        for malicious_string in malicious_strings:
            if malicious_string in content:
                return True  # Found suspicious string
    return False  # No suspicious string found


def check_file_with_virustotal_api(file_md5):
    """Check file MD5 with VirusTotal API"""
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': API_KEY,
        'resource': file_md5
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Check if the request was successful
        data = response.json()

        if data['response_code'] == 1:  # Assume response code 1 means results found
            return data  # Return relevant virus information
        else:
            return None  # No virus information found
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error: {http_err}")
        return None
    except Exception as e:
        print(f"API request error: {e}")
        return None


def scan_file(file_path):
    """Scan a single file and return results"""
    file_md5 = calculate_md5(file_path)
    result = f"File: {file_path}  MD5: {file_md5}\n"

    # Checking for local hash matches
    if file_md5 in virus_signatures:
        result += f'Virus found! Type: {virus_signatures[file_md5]}\n'
        return result, 'virus'

    # Check VirusTotal's virus database
    api_result = check_file_with_virustotal_api(file_md5)
    if api_result and api_result['positives'] > 0:
        result += f'Virus found! Detected by {
            api_result["positives"]} engines.\n'
        return result, 'virus'
    elif analyze_file_content(file_path):
        result += f'Suspicious string found!\n'
        return result, 'malicious_string'
    else:
        result += f'NO virus found\n'
        return result, 'safe'


def scan_directory(directory_path):
    """Scan all files in a directory and summarize results, including subdirectories"""
    results = []
    for root, _, files in os.walk(directory_path):  # Traverse all subfolders
        for file in files:
            file_path = os.path.join(root, file)
            # Scan each file and add results
            results.append(scan_file(file_path))
    return results


def show_results(results):
    """Display scan results in a text box"""
    result_text.delete(1.0, END)  # Clear previous content
    for result, result_type in results:
        # Set text color based on result type
        if result_type == 'virus':
            result_text.insert(END, result, 'virus')
        elif result_type == 'malicious_string':
            result_text.insert(END, result, 'malicious_string')
        else:
            result_text.insert(END, result)  # Safe file without color


def select_folder():
    """Select folders to scan"""
    folder_path = filedialog.askdirectory(title='Select folders to scan')
    if folder_path:
        results = scan_directory(folder_path)
        show_results(results)  # Display results


def select_file():
    """Select documents for scanning"""
    file_path = filedialog.askopenfilename(
        title='Select documents for scanning', filetypes=[('All files', '.*')])
    if file_path:
        result, result_type = scan_file(file_path)  # Scan file
        show_results([(result, result_type)])  # Display results


def thread_scan_folder():
    """Run a folder scan"""
    threading.Thread(target=select_folder).start()


def thread_scan_file():
    """Run a document scan"""
    threading.Thread(target=select_file).start()


def create_gui():
    """Create a GUI interface"""
    global result_text  # Declare as global variable for access in other functions
    window = Tk()
    window.title("Antivirus Software")
    window.geometry('600x400')

    label = Label(window, text="Welcome to Antivirus", font=("Arial", 14))
    label.pack(pady=20)

    scan_folder_button = Button(
        window, text="Scan Folders", command=thread_scan_folder)
    scan_folder_button.pack(pady=10)

    scan_file_button = Button(
        window, text="Scan Documents", command=thread_scan_file)
    scan_file_button.pack(pady=10)

    # Adding a scrolling text box
    result_text = Text(window, wrap='word', height=15, width=70)
    result_text.pack(pady=10)

    # Adding a Scroll Bar
    scrollbar = Scrollbar(window, command=result_text.yview)
    scrollbar.pack(side='right', fill='y')
    result_text.config(yscrollcommand=scrollbar.set)

    # Modify font color
    result_text.tag_config('virus', foreground='red')  # Red
    result_text.tag_config('malicious_string', foreground='blue')  # Blue

    window.mainloop()


if __name__ == '__main__':
    create_gui()
