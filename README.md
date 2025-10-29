# MDAA - AI Security Assistant Chrome Extension

The **Malware Deconstructor AI Agent (MDAA)** is a powerful browser extension designed for **malware analysts and cybersecurity researchers**. It integrates expert-level AI capabilities and direct access to public security intelligence platforms to streamline your analysis workflow directly within your browser.

> **Role Name:** Malware Deconstructor AI Agent
> **Expertise:** Expert-level assistant for malware analysts and cybersecurity researchers.
> **Goal:** Function as an intelligent colleague to augment user capabilities, not replace them.

---

## ✨ Features

* **AI Chat Interface:** Interact with the **Gemini 2.5 Flash** model, pre-configured with the **Malware Deconstructor AI Agent** persona for technical, precise, and collaborative security analysis.
    * **Contextual Analysis:** Use the right-click menu to send **selected text** or the **current page/link URL** directly to the chat or quick check tabs.
* **Quick IoC Check:** Analyze multiple Indicators of Compromise (IoCs) including **Hashes (MD5, SHA1, SHA256), IPv4 addresses, Domains, and URLs** in a single go.
    * **Integrated Threat Intelligence:** Supports lookups using **VirusTotal**, **AbuseIPDB**, and **Shodan** APIs (API keys required).
    * **AI Summarization:** Automatically summarize the combined results of your IoC checks with the AI Agent.
* **Page Analysis:** Dedicated tab to analyze the content of the active tab.
    * **Summarize Page/Selection:** Get key security-related takeaways from the page or selected text.
    * **Extract IoCs:** Automatically extract all IoCs from the content.
* **Secure Key Management:** All API keys are **encrypted** using **AES-GCM (256-bit)** and a password-derived key (via **PBKDF2 SHA-256 with 250,000 iterations**) and stored in Chrome's local storage.
    * Keys are decrypted only **in-memory** per session.
* **Chat History:** Option to save chat history persistently in local storage or session-only (default).

---

## ⚙️ Dependencies & API Keys

This extension requires API keys for full functionality:

| Platform | Required for | Manifest URL/Permission |
| :--- | :--- | :--- |
| **Google Gemini API** | AI Chat, Summarization, IoC Extraction | `https://generativelanguage.googleapis.com/` |
| **VirusTotal API** | Hash, Domain, IPv4, URL Quick Check | `https://www.virustotal.com/` |
| **AbuseIPDB API** | IPv4 Quick Check | `https://api.abuseipdb.com/` |
| **Shodan API** | IPv4 Quick Check (Optional) | N/A (API call made via `fetch`) |

---

## 🔒 Security & Key Management

### Syncing Keys

1.  Go to **Extension Options** (Right-click MDAA icon > Options).
2.  Click **"Start Sync from Web App"**.
3.  A new tab will open to the dedicated sync URL (`https://dashsecurity.netlify.app/mdaa`).
4.  You will be prompted to enter your web app password to **decrypt** the stored keys.
5.  You will then be prompted to set a **NEW, strong password** (min 12 chars) specifically for the extension.
6.  The keys are re-encrypted with the new password and securely saved to the extension's local storage.

### Session Unlock

* Every time you open the extension pop-up, you must enter your **Extension Password** to decrypt the API keys for that browsing session only.

---

## ⚠️ Safety Warning

The core AI component operates under a strict safety rule:
> You must **NEVER execute or run any code, binary, or command**. Static analysis only.

All AI analyses are performed by the model and must end with a warning:
> **⚠️ Further verification required: This analysis is performed by AI.**

---
