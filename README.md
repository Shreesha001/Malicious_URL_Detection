# 🔐 Malicious URL Detection Using DNS

This is a web-based application that helps detect whether a given URL is **malicious** or **safe**. The detection logic is based primarily on **DNS resolution** along with several intelligent heuristic checks (blacklist, suspicious keywords, etc.).

---


## 📁 Project Structure

```
malicious-url-checker/
├── backend/
│   ├── app.py              # Flask server with detection logic
│   ├── utils.py            # Utility functions for URL analysis
│   ├── blacklist.txt       # Sample domain blacklist
├── frontend/
│   ├── index.html          # Main HTML page
│   ├── script.js           # Frontend logic to call backend
│   ├── style.css           # Custom styles (optional, supports Tailwind)
├── README.md               # Project documentation
```

---

## ⚙️ Features

- 🛡️ Real-time malicious URL checking
- 🌐 DNS resolution logic to identify inactive domains
- 📛 Blacklist check from a local file
- 🔍 Suspicious keyword and TLD detection 

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.7+
- Flask
- Flask-CORS

### 📦 Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

You can manually install as well:

```bash
pip install flask flask-cors
```

### ▶️ Run Backend

```bash
python app.py
```

The Flask server will start at: `http://127.0.0.1:5000`

### 🌐 Open Frontend

Simply open `frontend/index.html` in your browser.

> Ensure CORS is enabled and the Flask server is running.

---

## 🧠 How it Works

When a user enters a URL, the backend performs:

1. ✅ **Domain extraction** from the URL
2. 🚫 **IP-only domain** check (suspicious)
3. 🔍 **Blacklist match** (locally stored)
4. ⚠️ **Suspicious keyword** check in domain/path
5. 📏 **Domain length** check
6. 🌍 **Suspicious TLD** detection and resolution test
7. 🧪 **DNS resolution** (final pass/fail check)

If DNS fails or suspicious flags are raised, the domain is marked **malicious**.

---
   