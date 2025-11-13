console.log("MDAA Sync Content Script Injected (waiting for CryptoHelper...).");

function executeSyncLogic() {
    (async () => {
        console.log("CryptoHelper found, executing main logic.");
        const CryptoHelper = window.CryptoHelper;
        const extensionId = window.MDAA_EXTENSION_ID; 
        const modalHTML = `
            <div id="mdaa-sync-overlay"></div>
            <div id="mdaa-sync-modal">
                <h3 id="mdaa-sync-title"></h3>
                <p id="mdaa-sync-message"></p>
                <input type="password" id="mdaa-sync-input">
                <p id="mdaa-sync-status"></p>
                <div id="mdaa-sync-buttons">
                    <button id="mdaa-sync-cancel-btn" class="mdaa-sync-btn">Cancel</button>
                    <button id="mdaa-sync-ok-btn" class="mdaa-sync-btn">Submit</button>
                </div>
            </div>
        `;

        if (extensionId) {
            const styleLink = document.createElement('link');
            styleLink.rel = 'stylesheet';
            styleLink.type = 'text/css';
            styleLink.href = `chrome-extension://${extensionId}/lib/modal.css`;
            document.head.appendChild(styleLink);
        } else {
            console.error("MDAA Sync: Extension ID not found.");
        }


        document.body.insertAdjacentHTML('beforeend', modalHTML);

        const overlay = document.getElementById('mdaa-sync-overlay');
        const modal = document.getElementById('mdaa-sync-modal');
        const titleEl = document.getElementById('mdaa-sync-title');
        const messageEl = document.getElementById('mdaa-sync-message');
        const inputEl = document.getElementById('mdaa-sync-input');
        const statusEl = document.getElementById('mdaa-sync-status');
        let okBtn = document.getElementById('mdaa-sync-ok-btn');
        let cancelBtn = document.getElementById('mdaa-sync-cancel-btn');

        const showModal = () => {
            overlay.style.display = 'block';
            modal.style.display = 'flex';
        };

        const hideModal = () => {
            overlay.style.display = 'none';
            modal.style.display = 'none';
        };

        function showCustomPrompt(title, message) {
            return new Promise((resolve) => {
                titleEl.textContent = title;
                messageEl.textContent = message;
                
                inputEl.style.display = 'block';
                inputEl.value = '';
                statusEl.textContent = '';
                cancelBtn.style.display = 'inline-block';
                okBtn.textContent = 'Submit';
                
                showModal();
                inputEl.focus();

                const newOkBtn = okBtn.cloneNode(true);
                okBtn.parentNode.replaceChild(newOkBtn, okBtn);
                okBtn = newOkBtn;

                const newCancelBtn = cancelBtn.cloneNode(true);
                cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
                cancelBtn = newCancelBtn;

                okBtn.onclick = () => {
                    hideModal();
                    resolve(inputEl.value);
                };

                cancelBtn.onclick = () => {
                    hideModal();
                    resolve(null); 
                };
                
                inputEl.onkeydown = (e) => {
                    if (e.key === 'Enter') {
                        okBtn.click();
                    }
                };
            });
        }

        function showCustomAlert(message, statusType = 'info') {
            return new Promise((resolve) => {
                titleEl.textContent = 'MDAA Sync Status';
                messageEl.textContent = '';
                
                inputEl.style.display = 'none';
                cancelBtn.style.display = 'none';
                okBtn.textContent = 'OK';
                
                statusEl.textContent = message;
                statusEl.className = statusType === 'error' ? 'mdaa-status-error' : (statusType === 'success' ? 'mdaa-status-success' : '');
                
                showModal();

                const newOkBtn = okBtn.cloneNode(true);
                okBtn.parentNode.replaceChild(newOkBtn, okBtn);
                okBtn = newOkBtn;

                const newCancelBtn = cancelBtn.cloneNode(true);
                cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
                cancelBtn = newCancelBtn;
                cancelBtn.style.display = 'none';

                okBtn.onclick = () => {
                    hideModal();
                    resolve();
                };
            });
        }
        
        if (!CryptoHelper) {
            console.error("MDAA Sync Error: CryptoHelper library was not injected correctly.");
            await showCustomAlert("Error: Critical sync component (CryptoHelper) failed to load. Please try again.", "error");
            return;
        }

        const password = await showCustomPrompt(
            "MDAA Extension Sync",
            "Please enter your MDAA web app encryption password to decrypt keys:"
        );

        if (!password) {
            await showCustomAlert("Sync cancelled. No password entered.", "error");
            return;
        }

        const WEB_APP_STORAGE_KEY = "_mdaa_api_keys_v1";
        const encryptedDataString = localStorage.getItem(WEB_APP_STORAGE_KEY);

        if (!encryptedDataString) {
            await showCustomAlert("Error: No encrypted keys found in the web app's storage. Please save keys in the web app first.", "error");
            return;
        }

        try {
            const encryptedData = JSON.parse(encryptedDataString);
            const decryptedKeysJSON = await CryptoHelper.decrypt(encryptedData, password);

            if (decryptedKeysJSON) {
                console.log("Keys decrypted. Now prompting for new extension password.");
                
                const newPassword = await showCustomPrompt(
                    "Set Extension Password",
                    "Please set a NEW, strong password for the browser extension (min 12 chars)."
                );

                if (!newPassword || newPassword.length < 12) {
                    await showCustomAlert("Password too short (min 12 chars). Sync cancelled.", "error");
                    return;
                }

                const confirmPassword = await showCustomPrompt(
                    "Confirm Password",
                    "Please re-enter your new password to confirm."
                );

                if (newPassword !== confirmPassword) {
                    await showCustomAlert("Passwords do not match. Sync cancelled.", "error");
                    return;
                }

                const newEncryptedData = await CryptoHelper.encrypt(decryptedKeysJSON, newPassword);
                console.log("Keys re-encrypted. Sending to background script.");
                
               
                chrome.runtime.sendMessage(extensionId, { type: "SYNC_ENCRYPTED_BLOB", data: newEncryptedData }, async (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Error sending keys to background:", chrome.runtime.lastError.message);
                        await showCustomAlert(`Error sending keys to extension: ${chrome.runtime.lastError.message}`, "error");
                    } else if (response && response.status === "success") {
                        console.log("Background script confirmed receipt.");
                        await showCustomAlert("Sync successful! Keys saved to extension. You may close this tab.", "success");
                    } else {
                         console.error("Background script response error:", response);
                         await showCustomAlert(`Extension did not confirm receipt: ${response?.message || 'Unknown error'}`, "error");
                    }
                });

            } else {
                await showCustomAlert("Decryption failed. Wrong password?", "error");
            }
        } catch (error) {
            console.error("Error during content script sync:", error);
            await showCustomAlert(`An error occurred during sync: ${error.message}`, "error");
        }
    })();
}

function pollForCryptoHelper(retryCount = 0) {
    if (window.CryptoHelper) {
        executeSyncLogic();
    } else if (retryCount < 50) { 
        setTimeout(() => pollForCryptoHelper(retryCount + 1), 100);
    } else {
        (async () => {
            if (!document.body) { 
                 setTimeout(() => pollForCryptoHelper(retryCount), 100);
                 return;
            }
            const el = document.createElement('div');
            el.style = "position:fixed;top:20px;left:50%;transform:translateX(-50%);background:red;color:white;padding:10px;border-radius:5px;z-index:10000;font-family:sans-serif;";
            el.textContent = "MDAA Sync Error: CryptoHelper component failed to load. Please close this tab and try again.";
            document.body.appendChild(el);
        })();
    }
}

if (document.readyState === 'complete' || document.readyState === 'interactive') {
    pollForCryptoHelper();
} else {
    document.addEventListener('DOMContentLoaded', pollForCryptoHelper);
}