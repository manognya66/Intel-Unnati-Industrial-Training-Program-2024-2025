# Protecting-User-Password-Keys-at-Rest-on-the-Disk
File Encryption and Decryption Application
This project is a secure file encryption and decryption application that uses AES-256 encryption and is protected by a user-defined passphrase. The application ensures that both the file encryption key and the passphrase are securely stored and handled.

Features:
  
    Encrypt files: Encrypts a user-chosen file or directory using a random File Encryption Key (FEK).
  
    Store encryption key securely: The FEK is stored in an encrypted form, protected by a user-defined passphrase.
  
    Secure passphrase handling: The passphrase and the FEK are not stored in plaintext.
  
    Decrypt files: Decrypts the encrypted file if the correct passphrase is provided.
  
    Brute-force protection: Includes a brute-force recovery mechanism for educational purposes.

Prerequisites:
    
    Operating System: Linux
    
    Hardware: Any x86-based Desktop or Server

Installation
  
  Clone the repository:
    
    git clone https://github.com/manognya66/Intel-Unnati-Industrial-Training-Program-2024-2025.git
    
    cd Intel-Unnati-Industrial-Training-Program-2024-2025
  
  Install the required dependencies:
      
      pip install  cryptography==36.0.0
      
      pip install tkinter==8.6

Usage

  Running the Application
    
  Run the main application script:

    python gui.py

    Select the desired operation (Encrypt/Decrypt) and provide the necessary inputs (input file and passphrase).

  Brute-Force Recovery
    
    Enable the "Decrypt" operation.
    
    Provide the character set and the maximum length for the brute-force attempt.
  
    Click "Brute-Force Recover" to start the recovery process.

File Encryption Logic
  
    Key Derivation: Uses PBKDF2HMAC with SHA-256 to derive a Key Encryption Key (KEK) from the user passphrase.

Encryption:
  
    Generates a random File Encryption Key (FEK) and uses AESGCM for encryption.
  
    Encrypts the FEK using the KEK and stores it along with salts and nonces.
  
Decryption:
  
    Derives the KEK from the user passphrase and decrypts the stored FEK.
  
    Uses the FEK to decrypt the file.

Example

  Steps for Encrypting a File
    
    Select "Encrypt" operation.
    
    Browse and select the input file.

    Enter a passphrase.
    
    Click "Encrypt" to encrypt the file.

Steps for Decrypting a File
    
    Select "Decrypt" operation.
    
    Browse and select the encrypted file.
    
    Enter the correct passphrase.
    
    Click "Decrypt" to decrypt the file.

Steps for Brute-Force Recovery
    
    Select "Decrypt" operation.

Contact
    
    For any questions or suggestions, feel free to contact me manognya71003@gmail.com.
