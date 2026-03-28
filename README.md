
````markdown
# 🔍 R_$ScanVuln$_L - Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Web%20Scanner-red)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

> A Python-based web vulnerability scanner designed to test common web security vulnerabilities.

---

# 📖 About

**R_$ScanVuln$_L** is a lightweight command‑line vulnerability scanner built with Python.  
It helps security researchers and penetration testers quickly test websites for common security vulnerabilities.

The tool sends crafted payloads to a target URL and analyzes the response to detect potential weaknesses.

---

# ✨ Features

The scanner can test multiple common web vulnerabilities including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Information Disclosure
- Server-Side Request Forgery (SSRF)
- File Inclusion
- Directory Traversal
- Command Injection
- File Upload Vulnerabilities
- Denial of Service (DoS)
- Remote Code Execution (RCE)
- Open Redirect

It also supports:

- 🎨 Colored terminal output
- ⏳ Loading animation
- 📊 Interactive scanning menu
- 🔎 Full automated scan option

---

# 📥 Installation

## 1️⃣ Requirements

- Python **3.8+**
- pip

Required Python libraries:

- requests
- colorama
- pyfiglet

---

## 2️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/vulnarbilityes_scanning.git
cd vulnarbilityes_scanning
````

---

## 3️⃣ Install Dependencies

Create a `requirements.txt` file with the following content:

```txt
requests
colorama
pyfiglet
```

Then install them:

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

Run the scanner:

```bash
python scanner.py
```

When the program starts you will see a menu.

Example:

```
[1] Scan for SQL Injection
[2] Scan for XSS
[3] Scan for CSRF
[4] Scan for Information Disclosure
[5] Scan for SSRF
[6] Scan for File Inclusion
[7] Scan for Directory Traversal
[8] Scan for Command Injection
[9] Scan for File Upload
[10] Scan for Denial of Service
[11] Scan for Remote Code Execution
[12] Scan for Open Redirect
[13] Scan All Vulnerabilities
[0] Exit
```

---

# 🔎 Example

```
Enter your choice: 1
Enter the target URL: http://example.com/page.php
```

The scanner will attempt different payloads and report potential vulnerabilities.

Example output:

```
[+] Potential SQL Injection found: http://example.com/page.php?id=' OR '1'='1
```

---

# 📂 Project Structure

```
R_ScanVuln_L/
│
├── scanner.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

# ⚠️ Disclaimer

This tool is developed **for educational purposes and authorized security testing only**.

Do **NOT** use this tool against websites or systems without **explicit permission** from the owner.

Unauthorized scanning may be illegal.

---

# 🤝 Contributing

Contributions are welcome.

You can help by:

* Adding new vulnerability checks
* Improving payload lists
* Optimizing detection logic
* Fixing bugs

Create a **Pull Request** or open an **Issue**.

---

# 📜 License

This project is licensed under the **MIT License**.

---

# 👨‍💻 Author

Developed by **Rakan Al‑Maliki**

Cyber Security Enthusiast
Python Security Tools Developer

---

⭐ If you like this project, consider giving it a **star** on GitHub.

```
