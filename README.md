# 🔍 Web Vulnerability Scanner

A simple Python-based **web vulnerability scanner** that detects **SQL Injection** and **Cross-Site Scripting (XSS)**.  
It crawls target websites, collects forms and parameters, and tests them with crafted payloads. Results are saved in an **HTML report**.

---

## 🚀 Features
- Detects **SQL Injection (SQLi)**
- Detects **Cross-Site Scripting (XSS)**
- Crawls website links and forms automatically
- Supports both `GET` and `POST` parameters
- Generates detailed **HTML reports**

---

## 🛠️ Requirements
- Python 3.x  
- [Requests](https://pypi.org/project/requests/)  
- [BeautifulSoup4](https://pypi.org/project/beautifulsoup4/)

Install dependencies:
```bash
pip install requests beautifulsoup4
```

---

## ▶️ Usage
1. Clone this repo:
   ```bash
   git clone https://github.com/itsdasharath/vuln-scanner.git
   cd vuln-scanner
   ```

2. Run the scanner:
   ```bash
   python Vuln-Scanner.py -u http://example.com
   ```

3. After scanning, results are saved in:
   ```
   report_<domain>.html
   ```

---

## 📂 Example Output
Terminal:
```
[!] SQL Injection found at http://example.com/login.php using ' OR 1=1--
[!] XSS found at http://example.com/search?q= using <script>alert('XSS')</script>
```

Report file:
```html
report_example.com.html
```

---

## ⚠️ Disclaimer
This tool is for **educational purposes only**.  
Do **not** use it on websites without explicit permission.
