import hashlib
import os
import requests
from tkinter import *
from tkinter import messagebox, filedialog
import threading

# MD5 hash signature library of known viruses
virus_signatures = {
    'eda588c0ee78b585f645aa42eff1e57a': '恶搞程序：Trojan.Win32.FormatAll.V',
    '19dbec50735b5f2a72d4199c4e184960': '病毒：Trojan.Win32.MEMZ.A',
    '815b63b8bc28ae052029f8cbdd7098ce': '恶搞程序：Virus.Win32.Blamon',
    'c71091507f731c203b6c93bc91adedb6': '未知病毒1',
    '0a456ffff1d3fd522457c187ebcf41e4': '未知病毒2',
    '1aa4c64363b68622c9426ce96c4186f2': '未知病毒3',
    'd214c717a357fe3a455610b197c390aa': '未知病毒4',
    'b14299fd4d1cbfb4cc7486d978398214': '未知病毒5',
    'dffe6e34209cb19ebe720c457a06edd6': '未知病毒6',
    '512301c535c88255c9a252fdf70b7a03': '未知病毒7',
    'd4a05ada747a970bff6e8c2c59c9b5cd': '未知病毒8',
    'ad41ec81ab55c17397d3d6039752b0fd': '未知病毒9',
    'a57db79f11a8c58d27f706bc1fe94e25': '未知病毒10',
    'fc14eaf932b76c51ebf490105ba843eb': '未知病毒11',
    '2a92da4b5a353ca41de980a49b329e7d': '未知病毒12',
    '68abd642c33f3d62b7f0f92e20b266aa': '未知病毒13',
    'ff5e1f27193ce51eec318714ef038bef': '未知病毒14',
    '4c36884f0644946344fa847756f4a04e': '未知病毒15',
    '2391109c40ccb0f982b86af86cfbc900': '未知病毒16',
    '915178156c8caa25b548484c97dd19c1': '未知病毒17',
    'dac5f1e894b500e6e467ae5d43b7ae3e': '未知病毒18',
    '84c82835a5d21bbcf75a61706d8ab549': '未知病毒19',
    'db349b97c37d22f5ea1d1841e3c89eb4': '未知病毒20',
    '1de73f49db23cf5cc6e06f47767f7fda': '未知病毒21',
    '71b6a493388e7d0b40c83ce903bc6b04': '未知病毒22',
    'b1a85fdd944c21070a0551e8c59a6158': '未知病毒23',
    'e60e767e33acf49c02568a79d9cbdadd': '未知病毒24',
    'f5ecda7dd8bb1c514f93c09cea8ae00d': '未知病毒25',
    '6cdcb9f86972efc4cfce4b06b6be053a': '未知病毒26',
    'f785b1a9a657aca7e70d16ac5effaabd': '未知病毒27',
    'ebcdda10fdfaa38e417d25977546df4f': '未知病毒28',
    'e22638ce44a5f9faf9dd450438c1d492': '未知病毒29',
    'de35f0262c089cc880fe8cee5d6b0156': '未知病毒30',
    'a635d6a35c2fc054042b6868ef52a0c3': '未知病毒31',
    'c4391b3b073bb1354afef0f1260b8fb8': '未知病毒32',
    'cd8c86863628f4d0c7f54fc3350fb1d9': '未知病毒33',
    'af6d91121887f5bb0a85a06b1ded0db7': '未知病毒34',
    '29b1550a1de57efda52b039aedeb4710': '后门病毒1',
    '203c4f24052a8df191e7c9fdc74a3b38': '后门病毒2',
    '7d8dcebef26d40a717a1dbdf895c8676': '后门病毒3', 
    'b9b5ce28fab628f9e15a4fddc031e902':'exercise'
}

# Simple list of malicious strings (for string matching)
malicious_strings = [
    "malware",
    "virus",
    "trojan",
    "ransomware",
    "exploit",
    # 其他可疑字符串...
]

API_KEY = 'dc1af1bd484306c9c114e929a3c96a9e8b99fa22851da0dfc4a57b8378116a3e'  # VirusTotal API密钥

def calculate_md5(file_path):
    """计算文件的MD5哈希值"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def analyze_file_content(file_path):
    """分析文件内容以查找可疑字符串"""
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
        for malicious_string in malicious_strings:
            if malicious_string in content:
                return True  # 找到可疑字符串
    return False  # 未找到可疑字符串

def check_file_with_virustotal_api(file_md5):
    """通过VirusTotal API检查文件MD5"""
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': API_KEY,
        'resource': file_md5
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # 检查请求是否成功
        data = response.json()

        if data['response_code'] == 1:  # 假设返回的状态码为1表示找到结果
            return data  # 返回相关的病毒信息
        else:
            return None  # 未找到病毒信息
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP错误: {http_err}")
        return None
    except Exception as e:
        print(f"API请求错误: {e}")
        return None

def scan_file(file_path):
    """扫描单个文件并返回结果"""
    file_md5 = calculate_md5(file_path)
    result = f"文件: {file_path}  MD5: {file_md5}\n"

    # Checking for local hash matches
    if file_md5 in virus_signatures:
        result += f'virus found！类型：{virus_signatures[file_md5]}\n'
        return result, 'virus'
    
    # Check VirusTotal's virus database
    api_result = check_file_with_virustotal_api(file_md5)
    if api_result and api_result['positives'] > 0:
        result += f'virus found！检测到的引擎数量：{api_result["positives"]}\n'
        return result, 'virus'
    elif analyze_file_content(file_path):
        result += f'Suspicious string found！\n'
        return result, 'malicious_string'
    else:
        result += f'NO virus found\n'
        return result, 'safe'

def scan_directory(directory_path):
    """扫描目录中的所有文件并汇总结果，包括子目录"""
    results = []
    for root, _, files in os.walk(directory_path):  # 遍历所有子文件夹
        for file in files:
            file_path = os.path.join(root, file)
            results.append(scan_file(file_path))  # 扫描每个文件并添加结果
    return results

def show_results(results):
    """Displaying scan results in a text box"""
    result_text.delete(1.0, END)  # 清除之前的内容
    for result, result_type in results:
        # 根据结果类型设置文本颜色
        if result_type == 'virus':
            result_text.insert(END, result, 'virus')
        elif result_type == 'malicious_string':
            result_text.insert(END, result, 'malicious_string')
        else:
            result_text.insert(END, result)  # 安全文件不设置颜色

def select_folder():
    """Selecting folders to scan"""
    folder_path = filedialog.askdirectory(title='Selecting folders to scan')
    if folder_path:
        results = scan_directory(folder_path)
        show_results(results)  # 显示结果

def select_file():
    """Selecting documents for scanning"""
    file_path = filedialog.askopenfilename(title='Selecting documents for scanning', filetypes=[('所有文件', '.*')])
    if file_path:
        result, result_type = scan_file(file_path)  # 扫描文件
        show_results([(result, result_type)])  # 显示结果

def thread_scan_folder():
    """Run a folder scan"""
    threading.Thread(target=select_folder).start()

def thread_scan_file():
    """Run a document scan"""
    threading.Thread(target=select_file).start()

def create_gui():
    """Creating a GUI interface"""
    global result_text  # 声明为全局变量，以便在其他函数中访问
    window = Tk()
    window.title("antivirus software")
    window.geometry('600x400')

    label = Label(window, text="Welcome to Antivirus", font=("Arial", 14))
    label.pack(pady=20)

    scan_folder_button = Button(window, text="Scan Folders", command=thread_scan_folder)
    scan_folder_button.pack(pady=10)

    scan_file_button = Button(window, text="Scan Documents", command=thread_scan_file)
    scan_file_button.pack(pady=10)

    # Adding a scrolling text box
    result_text = Text(window, wrap='word', height=15, width=70)
    result_text.pack(pady=10)

    # Adding a Scroll Bar
    scrollbar = Scrollbar(window, command=result_text.yview)
    scrollbar.pack(side='right', fill='y')
    result_text.config(yscrollcommand=scrollbar.set)

    # Modify font colour
    result_text.tag_config('virus', foreground='red')  # 红色
    result_text.tag_config('malicious_string', foreground='blue')  # 黄色

    window.mainloop()

if __name__ == '__main__':
    create_gui()