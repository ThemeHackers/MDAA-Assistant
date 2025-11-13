import { CryptoHelper } from './lib/crypto.js';

const API_KEYS_NAME = "_mdaa_api_keys_v1_ext";
const CHAT_HISTORY_SETTING = "saveChatHistory";
const SYNC_URL = "https://dashsecurity.netlify.app/mdaa";

const generalStatus = document.getElementById("general-status");
const manualStatus = document.getElementById("manual-status");
const syncBtn = document.getElementById("sync-from-web-btn");
const saveChatHistoryCheckbox = document.getElementById("save-chat-history-checkbox");
const encryptAndSaveBtn = document.getElementById("encrypt-and-save-btn");
const unsyncKeysBtn = document.getElementById("unsync-keys-btn");

const geminiKeyInput = document.getElementById("gemini-key-input");
const vtKeyInput = document.getElementById("vt-key-input");
const abuseKeyInput = document.getElementById("abuse-key-input");
const shodanKeyInput = document.getElementById("shodan-key-input");
const encryptionPasswordInput = document.getElementById("encryption-password-input");

const keyStatusElements = {
    gemini: document.getElementById("gemini-key-status"),
    virustotal: document.getElementById("vt-key-status"),
    abuseipdb: document.getElementById("abuse-key-status"),
    shodan: document.getElementById("shodan-key-status"),
};

const strengthProgress = document.getElementById('password-strength-progress-options');
const strengthText = document.getElementById('password-strength-text-options');


function showStatus(message, isSuccess, element = generalStatus) {
    element.textContent = message;
    element.className = isSuccess ? 'status-success' : 'status-error';
}

function updateKeyStatusDisplay(savedKeys) {
    const keysToCheck = ['gemini', 'virustotal', 'abuseipdb', 'shodan'];
    let keysSetCount = 0;

    keysToCheck.forEach(keyName => {
        const element = keyStatusElements[keyName];
        if (element) {
            if (savedKeys && savedKeys[keyName] && savedKeys[keyName].length > 0) {
                element.textContent = "Saved";
                element.className = "key-status saved";
                keysSetCount++;
            } else {
                element.textContent = "Not Set";
                element.className = "key-status not-set";
            }
        }
    });

    if (keysSetCount > 0) {
        showStatus(`Encrypted keys saved (${keysSetCount} API keys set).`, true, generalStatus);
    } else {
        showStatus("No API Keys are currently saved.", false, generalStatus);
    }
}

function checkPasswordStrength(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    score = Math.min(score, 4);

    strengthProgress.className = `strength-${score}`;
    let strengthMessage = '';
    if (password.length === 0) strengthMessage = '';
    else if (score === 1) strengthMessage = 'Weak (Min 12 chars recommended)';
    else if (score === 2) strengthMessage = 'Fair';
    else if (score === 3) strengthMessage = 'Good';
    else if (score >= 4) strengthMessage = 'Strong';
    
    strengthText.textContent = strengthMessage;
    
    return { score, isSufficient: score >= 3 };
}


syncBtn.addEventListener('click', async () => {
    showStatus("Opening sync tab...", true, generalStatus);
    try {

        const tab = await chrome.tabs.create({ url: SYNC_URL, active: true });

        const listener = (tabId, info, updatedTab) => {
            
            if (tabId === tab.id && info.status === 'complete' && updatedTab.url.startsWith(SYNC_URL)) {
                
                chrome.tabs.onUpdated.removeListener(listener); 

                (async () => {
                    try {
                        
                
                        await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            files: ["lib/crypto.global.js"],
                            world: "MAIN"
                        });


                        await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            func: (extensionId) => {
                                window.MDAA_EXTENSION_ID = extensionId;
                            },
                            args: [chrome.runtime.id],
                            world: "MAIN"
                        });

                        await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            files: ["lib/crypto.content.js"],
                            world: "MAIN"
                        });
                        
                        showStatus("Sync tab is ready. Please follow instructions on that page.", true, generalStatus);
                    
                    } catch (scriptError) {
                        
                        if (scriptError.message.includes("Frame with ID 0 was removed") || scriptError.message.includes("No frame with id")) {
                             console.error("Injection failed because the tab was closed or navigated away too quickly.", scriptError);
                             showStatus(`Sync failed: Tab was closed or changed. Please try again.`, false, generalStatus);
                        } else {
                            showStatus(`Error injecting scripts: ${scriptError.message}`, false, generalStatus);
                        }
                    }
                })(); 
            }
        };

        chrome.tabs.onUpdated.addListener(listener);

    } catch (e) {
        console.error("Sync tab creation failed:", e);
        showStatus(`Error starting sync: ${e.message}`, false, generalStatus);
    }
});

encryptionPasswordInput.addEventListener('input', (e) => {
    checkPasswordStrength(e.target.value);
});

encryptAndSaveBtn.addEventListener('click', async () => {
    const geminiKey = geminiKeyInput.value.trim();
    const vtKey = vtKeyInput.value.trim();
    const abuseKey = abuseKeyInput.value.trim();
    const shodanKey = shodanKeyInput.value.trim();
    const password = encryptionPasswordInput.value.trim();

    if (!geminiKey && !vtKey && !abuseKey && !shodanKey) {
        showStatus("Error: At least one API Key must be entered.", false, manualStatus);
        return;
    }
    
    const { isSufficient } = checkPasswordStrength(password);
    if (password.length < 12 || !isSufficient) {
        showStatus("Error: Encryption password must be at least 12 characters and strong.", false, manualStatus);
        return;
    }

    encryptAndSaveBtn.disabled = true;
    showStatus("Encrypting and saving keys...", true, manualStatus);

    const keysToEncrypt = {
        gemini: geminiKey,
        virustotal: vtKey,
        abuseipdb: abuseKey,
        shodan: shodanKey,
    };
    
    try {

        const keysJSON = JSON.stringify(keysToEncrypt);
        

        const encryptedData = await CryptoHelper.encrypt(keysJSON, password);

        await chrome.storage.local.set({ [API_KEYS_NAME]: encryptedData });
        

        geminiKeyInput.value = '';
        vtKeyInput.value = '';
        abuseKeyInput.value = '';
        shodanKeyInput.value = '';
        encryptionPasswordInput.value = '';
        checkPasswordStrength(''); 

        showStatus("Success! Keys are encrypted and securely saved.", true, manualStatus);
        await initializeOptionsPage(true); 

    } catch (e) {
        console.error("Manual save error:", e);
        showStatus(`Error during encryption/save: ${e.message}`, false, manualStatus);
    } finally {
        encryptAndSaveBtn.disabled = false;
    }
});

unsyncKeysBtn.addEventListener('click', async () => {
    if (!confirm("Are you sure you want to UNSYNC and PERMANENTLY DELETE ALL ENCRYPTED API KEYS from this extension's local storage?")) {
        return;
    }

    unsyncKeysBtn.disabled = true;
    showStatus("Deleting all encrypted keys...", true, manualStatus);
    
    try {

        await chrome.storage.local.remove(API_KEYS_NAME);
        
        await chrome.storage.session.remove('sessionKeys'); 
        

        geminiKeyInput.value = '';
        vtKeyInput.value = '';
        abuseKeyInput.value = '';
        shodanKeyInput.value = '';
        encryptionPasswordInput.value = '';
        checkPasswordStrength('');

        showStatus("Unsync successful! All encrypted keys have been deleted.", true, manualStatus);
        await initializeOptionsPage(true); 

    } catch (e) {
        console.error("Unsync error:", e);
        showStatus(`Error during unsync: ${e.message}`, false, manualStatus);
    } finally {
        unsyncKeysBtn.disabled = false;
    }
});

saveChatHistoryCheckbox.addEventListener('change', async () => {
    const isChecked = saveChatHistoryCheckbox.checked;
    await chrome.storage.local.set({ [CHAT_HISTORY_SETTING]: isChecked });
    showStatus("Setting saved. Please reload the extension (or browser) for changes to take effect.", true, generalStatus);
});


async function initializeOptionsPage(skipStatusUpdate = false) {
    const data = await chrome.storage.local.get([API_KEYS_NAME, CHAT_HISTORY_SETTING]);
    
    if (data[API_KEYS_NAME]) {

        updateKeyStatusDisplay(null); 

        try {

            const savedData = data[API_KEYS_NAME];
            if (savedData.salt && savedData.iv && savedData.data) {

                 updateKeyStatusDisplay({
                    gemini: 'key_present',
                    virustotal: 'key_present',
                    abuseipdb: 'key_present',
                    shodan: 'key_present'
                });
            } else {
                 updateKeyStatusDisplay(null);
                 showStatus("Encrypted keys found but data structure is invalid. Please resync/resave.", false, generalStatus);
            }
        } catch (e) {
             updateKeyStatusDisplay(null);
             showStatus("Error reading encrypted keys. Please resync/resave.", false, generalStatus);
        }
        
    } else {
        updateKeyStatusDisplay(null);
        if (!skipStatusUpdate) {
             showStatus("No keys found. Please use the Sync or Manual Setup sections to add your keys.", false, generalStatus);
        }
    }
    
    saveChatHistoryCheckbox.checked = data[CHAT_HISTORY_SETTING] || false;
}

initializeOptionsPage();
