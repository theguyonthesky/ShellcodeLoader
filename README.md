# Shellcode Loader

# Overview
The Shellcode Loader project demonstrates the process of loading and executing a shell in the target machine discreetly, utilizing a meticulously crafted C++ script. In conjunction with leveraging the potent Havoc C2 for post-exploitation command and control activities, the project accentuates a keen emphasis on maintaining a stealthy operational profile by employing dynamically resolved Windows API functions and AES decryption.

# Note
- Security and Ethical Notice: The information and code provided in this repository are meant for educational and research purposes only. Do not use the provided code and techniques for illegal activities.
  
# Features
- Dynamic Windows API Calls: Implements dynamic resolution of critical Windows API functions to facilitate stealthy memory allocation and shellcode execution.
- AES Decryption: Leverages Windows Cryptography API for decrypting AES-encrypted shellcode just before its execution, obfuscating its presence in memory and thereby mitigating certain detection vectors.
- Memory Injection – Allocates memory and executes the decrypted payload via a new thread.
- YARA Rule: A tailored YARA rule developed to identify the instances and usage of the shellcode loader by targeting strings and patterns indicative of cryptographic and memory manipulation API calls.
  
# How It Works
1. AES-encrypted shellcode and a decryption key are embedded in the loader.

2. Windows Crypto API is used to decrypt the payload in memory.

3. The loader dynamically resolves functions like VirtualAlloc, CreateThread, and CryptAcquireContext to evade static detection.

4. The decrypted shellcode is injected into memory and executed, bypassing Windows Defender due to the use of dynamic API resolution and encryption.

5. A YARA rule can be used to scan systems for artifacts of the loader.

# Tools and Technologies Used
- C++ – Main programming language

- Windows API – For memory allocation, cryptographic operations (including AES decryption using CryptAcquireContext, CryptDeriveKey, etc.), and process/thread management

- YARA – For writing and testing custom detection rules

# Files
- ShellCodeLoader.cpp: Contains the C++ code for the shellcode loader, involving dynamic API call resolution, AES decryption, and shellcode execution in a newly allocated memory region. Please reference this file for a detailed code walkthrough.
- ShellCodeYara.yara: A YARA rule designed to detect the presence or usage of the provided shellcode loader in analyzed files or memory, targeting API calls and characteristic strings.

# How to Run
1. Clone or download this repository
2. Set up dependencies and compile
    - ## Shellcode Loader
    - Dependencies: Requires a C++ compiler (e.g., MinGW, Visual Studio)
- Ensure the target system has the necessary Windows libraries for API calls.
    - Compilation: Compile ShellCodeLoader.cpp using a C++ compiler targeting the intended architecture (32/64 bit) with: g++ ShellCodeLoader.cpp -o ShellCodeLoader.exe -lcrypt32 -ladvapi32
  
    - ## YARA Rule
    - Dependencies: Install YARA: Refer to the official YARA documentation for installation and usage details.
    - Usage: Utilize ShellCodeYara.yara to scan files or memory for indications of the shellcode loader using: yara -r ShellCodeYara.yara [directory or file to scan]

## Disclaimer
While the shellcode loader and associated materials have been developed with research and educational objectives, the ethical and legal implications of its use are dependent upon user discretion. Ensure adherence to laws and guidelines relevant to your jurisdiction and organizational policies.

## Contribution & Feedback
Contributions, feedback, and issues can be submitted via the GitHub repository. Ensure that your interactions adhere to the GitHub Community Guidelines to maintain a respectful and collaborative environment.

## License
MIT License - Refer to the LICENSE file in the repository.
