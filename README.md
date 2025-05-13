# 🐭 Crack-A-Mauz

![Logo](https://github.com/mauzware/Mauzalyzer-assets/blob/main/crackamauz%20logo.png)

**Crack-A-Mauz is a professional-grade, multi-mode brute-force tool built for offensive security professionals, CTF players, and pentesters. It supports both classic dictionary-based brute-force attacks and rainbow table lookups, with optional proxy support and smart login detection. Built with customization, speed, and usability in mind.**

> **Created by [mauzware](https://github.com/mauzware)**  
> Works on Linux 🐧 and Windows 🧩  
> Fast, powerful, and customizable ⚙️

![Gif](https://github.com/mauzware/Mauzalyzer-assets/blob/main/cracker%20boi.gif)

---

## 🛠 <i>Features</i>

- 🧩 Hash identification and cracking

- 🔑 Username & password brute-force attacks

- 🌈 Rainbow table attacks (hash:plain format)

- 🚀 Speed modes: slow, standard, and fast

- 🔁 Auto-rate limiting on server errors

- 🧠 Smart login detection with keyword analysis

- 🌍 Proxy support (Burp Suite or custom list)

- 🎯 Beautiful output with live progress updates

- 💾 Saves successful hits to dict_hits.txt and rainbow_hits.txt

---

## ⚙️ <i>Installation</i>

Make sure you have **Python 3.9+** installed (tested on 3.13+). <br>
You can use either **pip** or **pip3**, whichever works on your system depending on your Python version.

<i>**Windows/Debian/Ubuntu**</i>

```
git clone https://github.com/mauzware/Crack-A-Mauz.git
cd Crack-A-Mauz
pip install -r requirements.txt
```

<i>**Kali Linux**</i>

In Kali, all modules are already preinstalled except `colorlog`

```
sudo apt install python3-colorlog

git clone https://github.com/mauzware/Crack-A-Mauz.git
cd Crack-A-Mauz
```

If you are missing some modules by any chance, you can install them with: <br>
1) Create a virtual environment and use: **pip3 install -r requirements.txt** <br>
2) Install them manually with apt: **sudo apt install python3-[module_name]**

---

## 📦 <i>**Dependencies**</i>

- `requests`

- `colorlog`

- `termcolor`

- `tqdm`

- `bs4 (BeautifulSoup4)`

---

## 🧪 <i>**Usage**</i>

```
python3 crackamauz.py
python crackamauz.py
```

Choose from the following modes:

```
[1] Identify Hash
[2] Cracks Hashes
[3] Brute Force - Dictionary Attack
[4] Brute Force - Rainbow Table Attack
[0] Exit
```

🔐 Brute Force Attack

- Provide a target login URL

- Enter paths to username & password wordlists

- Choose speed: slow, standard, fast

- Optional: Proxy usage via Burp or custom list

🌈 Rainbow Attack

- Provide target login URL

- Enter a static username

- Provide a rainbow table in `hash:password` format

- Optional: Proxy usage via Burp or custom list

📄 Example rainbow table format

```
5f4dcc3b5aa765d61d8327deb882cf99:password
d8578edf8458ce06fbc5bb76a58c5ca4:qwerty
e10adc3949ba59abbe56e057f20f883e:123456
```

📁 Output

- Valid credentials from brute-force saved to: `dict_hits.txt`

  ```
  [2025-05-12 16:03:31]http://testing.mauz/dvwa/login.php => Username: admin | Password: password
  ```

- Rainbow mode matches saved to: `rainbow_hits.txt`

  ```
  [2025-05-13 00:10:25]http://testing.mauz/dvwa/login.php => Username: admin | Password: password
  ```

📌 Notes

- Works best on targets that do not use JavaScript-based logins

- CSRF token support is not implemented yet, it will be in version 2.0

---

## ✅ <i>**Screenshots**</i>

**Hash identification and cracking**

![identification](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali%20hash%20identification.png)

![cracking](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali%20hash%20cracking.png)

**Dictionary attack without proxy**

![no proxy](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali%20brute%20longer%20lists.png)

**Dictionary attack with proxy**

![proxy](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali%20brute%20proxy.png)

**Rainbow table attack without proxy**

![no proxy](https://github.com/mauzware/Mauzalyzer-assets/blob/main/rainbow%20normal.png)

**Rainbow table attack with proxy**

![proxy](https://github.com/mauzware/Mauzalyzer-assets/blob/main/rainbow%20proxy.png)

⚠️ **Disclaimer**

All testing was conducted exclusively on DVWA (Damn Vulnerable Web Application) in a controlled lab environment for educational and research purposes only.

This tool is intended for authorized testing in environments you own or have explicit permission to test.

---

## 🚧 <i>Future Plans: Crack-A-Mauz v2.0 (coming soon...)</i>

- Additional support for other protocols/services (FTP, SSH)

- Smart field detection with BeautifulSoup

- Parallel multi-URL brute forcing

- Proxy rotation + Tor support

- Smarter CSRF Token handling

- Additional output formats

- Integrated hash identifier module

- Many more

---

## 👨‍💻 <i>**Author**</i>

Crack-A-Mauz was engineered with passion by [Mauzalyzer](https://github.com/mauzware/Mauzalyzer).

If you like the project, consider ⭐️ starring the repo and following for more tools.

[<img src="https://github.com/mauzware/mauzware/blob/main/LOGO%20NEW.png" width="140px" height="40px"/>](https://github.com/mauzware)

---

## 📜 <i>**License**</i>

This project is open-source and distributed under the terms of the MIT License. You are free to use, modify, and distribute it with proper attribution.

---

## ⚠️ <i>**Disclaimer**</i>

⚠️ The content in this repository is for educational and informational purposes only; the author holds no responsibility for misuse. 
Ensure proper authorization before use, act responsibly at your own risk, and comply with all legal and ethical guidelines. ⚠️





