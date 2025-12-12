# 🔐 Encrypted File Transfer System (Client-Server Project)

A cross-language secure file transfer application built with **C++** (Client) and **Python** (Server).  
This project enables encrypted file exchange over a network using **RSA**, **AES**, and **CRC** mechanisms  
to ensure confidentiality and integrity. <br><br>

## 📦 Features

🔑 **RSA**: Secure key exchange  
🔒 **AES**: Symmetric encryption for file contents  
✅ **CRC**: File integrity check using CRC32  
🔁 Reliable retry mechanism with automatic retransmission  
💬 Simple request/response custom binary protocol  
🧰 Modular C++ code using object-oriented design <br><br>

## 📁 Project Structure

* server/ - Python server code
* client/ - C++ client code with modular classes for networking, cryptography, and protocol handling <br><br>

## ⚙️ Configuration Files

The project includes two configuration files:

📄 **`transfer.info`**
Contains the server IP and port, client name, and the file name to send.

📄 **`port.info`**
Specifies the port number the server listens on.

---

#### Example contents:

```text
transfer.info:
127.0.0.1:8888
Moshe
Screenshot1.png

port.info:
8888
```

---

You can use these template files as-is or modify their contents as needed to fit your environment.  
🔔 Important: The port in transfer.info must match the port in port.info for the client and server to connect correctly. <br><br>

## 🚀 How to Run

### ✅ Prerequisites

* C++ compiler supporting C++11 or later (e.g., g++, MSVC)
* [Crypto++ library](https://www.cryptopp.com/) installed for cryptographic operations
* Python 3.6+

### 🖥️ Start the Server

```bash
cd server
python main.py
```

### 🖥️ Build and Run the Client

```bash
cd client
g++ -std=c++11 -o client main.cpp client.cpp crypt.cpp -lcryptopp -lws2_32  # for Windows
./client  # on Linux/macOS
```

<br><br>

## 🛠️ Technologies Used

* C++ - Client logic, networking, cryptography with Crypto++
* Python - Server logic and file handling
* RSA/AES - Encryption and secure key exchange
* CRC32 - File integrity verification
* TCP Sockets - Client-server communication over a custom binary protocol
