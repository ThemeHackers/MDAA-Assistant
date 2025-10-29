# Security Policy for MDAA - AI Security Assistant Extension

## 🔒 Security Goal

The primary security goal of the MDAA extension is to **protect the user's sensitive API keys**. All keys are handled with client-side encryption and are never stored in plain text.

## 🔑 Key Management and Encryption

* **Encryption Standard:** API keys are encrypted using **AES-GCM (256-bit)**.
* **Key Derivation:** The encryption key is derived from the user's password using **PBKDF2 with SHA-256** and a high iteration count of **250,000** to resist brute-force attacks.
* **Storage:** The encrypted blob (containing the salt, IV, and ciphertext) is stored in the browser's **`chrome.storage.local`** with the key `_mdaa_api_keys_v1_ext`.
* **Session Security:** The decrypted API keys are stored only in **`chrome.storage.session`** (`sessionKeys`) upon successful password entry in the popup. They are *only* available for the current browsing session and are cleared when the browser session ends.

## 🌐 External Connections

The extension's network activity is strictly limited by the `host_permissions` in the manifest:

* `https://generativelanguage.googleapis.com/`: For all AI/Gemini API calls.
* `https://www.virustotal.com/`: For VirusTotal lookups.
* `https://api.abuseipdb.com/`: For AbuseIPDB lookups.
* `https://dashsecurity.netlify.app/*`: For the secure initial key sync process, as an `externally_connectable` host. Shodan API calls are made to `https://api.shodan.io/` which is not in `host_permissions`, but this is acceptable for Chrome extensions if done via the `fetch` API from a standard script without requiring broad `host_permissions`.

## 🐛 Reporting a Vulnerability

If you discover a security vulnerability within the MDAA extension, please **DO NOT** disclose it publicly.

1.  **Contact:** Please report the issue privately by contacting [Insert preferred security email or channel here].
2.  **Details:** Provide a detailed description of the vulnerability, including:
    * The file(s) and line number(s) where the vulnerability exists.
    * Steps to reproduce the issue.
    * The potential impact of the vulnerability.

We will acknowledge your report and work to address the issue as quickly as possible.

---
