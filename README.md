# TLSInspector

**TLSInspector** is a Python command-line tool designed to scan servers for supported TLS/SSL ciphers, classify them as secure or weak based on [ciphersuites.info](https://ciphersuites.info), check for legacy protocols, and provide actionable recommendations to harden server security. It helps security professionals, system administrators, and developers quickly audit the TLS configuration of servers.

## Features
- Scan **TLS 1.2** and **TLS 1.3** ciphers.
- Highlight **secure ciphers in green** and **weak ciphers in red**.
- Check for **legacy protocol support**: SSLv3, TLS 1.0, TLS 1.1.
- Provide recommendations to **remove weak ciphers** or **add secure ciphers**.
- Command-line interface (CLI) for quick and easy use.
- Open-source and lightweight.

## Installation
1. Clone the repository:
```bash
git clone https://github.com/Tushar-V27/TLSInspector.git
cd TLSInspector
```
2. Install required dependencies:
```bash
pip install -r requirements.txt
```
(Windows users may need colorama for full terminal color support.)


**Usage**


Run the tool using Python:
```bash
python tls_inspector.py
```

You will be prompted to enter:

Server domain (e.g., example.com)

Port (default 443)

Example:
```bash
Enter server domain: chatgpt.com
Enter port [default 443]: 443
```

**The tool will output:**
1. Supported TLS 1.2 and 1.3 ciphers.
2. Classification of secure vs weak ciphers.
3. Legacy protocol support.
4. Recommendations to improve TLS security.


**Secure vs Weak Classification**
TLSInspector follows [ciphersuites.info](https://ciphersuites.info) for classifying ciphers:

1. Green: Recommended secure ciphers.
2. Red: Weak or outdated ciphers.
   Recommendations suggest removing weak ciphers or adding secure ones.


**Contribution**

Contributions are welcome! Feel free to open issues, submit pull requests, or suggest improvements.


**Disclaimer**

TLSInspector is intended for security auditing and educational purposes only. Ensure you have permission to scan any server.

```vbnet
This is **ready to copy and paste fully** into your GitHub repo.  

If you want, I can now also give you a **ready-to-use `requirements.txt` and folder structure** so you can directly push TLSInspector to GitHub. Do you want me to do that?
```
