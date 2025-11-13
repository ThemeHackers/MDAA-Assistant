import { CryptoHelper } from './lib/crypto.js';
import { callGeminiAPI, getVTResponse, checkAbuseIPDB, checkShodan } from './lib/api.js'; 

const API_KEYS_NAME = "_mdaa_api_keys_v1_ext";
const MAX_PAGE_CONTENT_LENGTH = 15000;
const SESSION_CHAT_HISTORY_KEY = "sessionChatHistory";
const LOCAL_CHAT_HISTORY_KEY = "_mdaa_chat_history";
const CHAT_HISTORY_SETTING = "saveChatHistory";
const CHAT_HISTORY_WINDOW_SIZE = 20;
const ALL_SESSIONS_KEY = "_mdaa_all_chat_sessions_v1";

const FAILED_ATTEMPTS_KEY = "failedUnlockAttempts";
const LOCKOUT_END_TIME_KEY = "lockoutEndTime";
const MAX_ATTEMPTS_BEFORE_DELAY = 3;
const LOCKOUT_POLICY = {
    4: 5000,
    5: 20000,
    6: 60000,
    8: 300000
};

let sessionKeys = null;
let aiHistory = [];
let usePersistentHistory = false;

const lockedView = document.getElementById('locked-view');
const unlockedView = document.getElementById('unlocked-view');
const passwordInput = document.getElementById('session-password-input');
const unlockBtn = document.getElementById('unlock-session-btn');
const unlockStatus = document.getElementById('unlock-status-message');
const goToOptionsBtn = document.getElementById('go-to-options');
const removeSessionKeysBtn = document.getElementById('remove-session-keys-btn'); 

const tabs = document.querySelectorAll('.tab-link');
const tabContents = document.querySelectorAll('.tab-content');

const chatView = document.getElementById('chat-view');
const historyView = document.getElementById('history-view');
const chatContainer = document.getElementById('chat-container');
const chatInput = document.getElementById('chat-input');
const sendChatBtn = document.getElementById('send-chat-btn');
const newChatBtn = document.getElementById('new-chat-btn');
const historyChatBtn = document.getElementById('history-chat-btn');
const backToChatBtn = document.getElementById('back-to-chat-btn');
const historyListContainer = document.getElementById('history-list-container');

const iocInput = document.getElementById('ioc-input');
const smartCheckBtn = document.getElementById('smart-check-btn');
const quickCheckResults = document.getElementById('quick-check-results');
const qcAiAnalyzeBtn = document.getElementById('qc-ai-analyze-btn');
const qcAiAnalyzeGroup = document.getElementById('qc-ai-analyze-group');
const summarizePageBtn = document.getElementById('summarize-page-btn');
const extractBtn = document.getElementById('extract-iocs-btn');

const storageArea = () => usePersistentHistory ? chrome.storage.local : chrome.storage.session;
const chatHistoryKey = () => usePersistentHistory ? LOCAL_CHAT_HISTORY_KEY : SESSION_CHAT_HISTORY_KEY;

function validateSessionKeys(keys) {
    if (typeof keys !== 'object' || keys === null) return false;
    if (!keys.gemini) return false; 
    if (!keys.virustotal && !keys.abuseipdb && !keys.shodan) {
        console.warn("Session keys loaded, but core analysis keys (VT/Abuse/Shodan) are missing.");
    }
    return true;
}

document.addEventListener('DOMContentLoaded', async () => {
    const chatSetting = await chrome.storage.local.get(CHAT_HISTORY_SETTING);
    usePersistentHistory = chatSetting[CHAT_HISTORY_SETTING] || false;

    const session = await chrome.storage.session.get('sessionKeys');
    
    if (session.sessionKeys && validateSessionKeys(session.sessionKeys)) {
        sessionKeys = session.sessionKeys;
        await showView('unlocked');
        await handleContextData();
    } else {
        if (session.sessionKeys) {
            console.warn("Invalid session keys detected in storage. Clearing session.");
            await chrome.storage.session.remove('sessionKeys');
        }
        
        const data = await chrome.storage.local.get(API_KEYS_NAME);
        if (data[API_KEYS_NAME]) {
            showView('locked');
        } else {
            showView('no_keys');
        }
    }

    unlockBtn.addEventListener('click', handleUnlock);
    goToOptionsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());
    removeSessionKeysBtn.addEventListener('click', handleRemoveSessionKeys); 
    tabs.forEach(tab => tab.addEventListener('click', handleTabClick));
    sendChatBtn.addEventListener('click', handleSendChat);
    smartCheckBtn.addEventListener('click', handleSmartCheck);
    qcAiAnalyzeBtn.addEventListener('click', handleQcAiAnalyze);
    summarizePageBtn.addEventListener('click', () => handlePageAnalysis('summarize'));
    extractBtn.addEventListener('click', () => handlePageAnalysis('extract_iocs'));

    newChatBtn.addEventListener('click', handleNewChat);
    historyChatBtn.addEventListener('click', showHistoryView);
    backToChatBtn.addEventListener('click', showChatView);
});

async function handleRemoveSessionKeys() {
    if (confirm("Are you sure you want to remove the decrypted API keys from this browser session? You will need to re-enter your password to use the extension again.")) {
        sessionKeys = null;
        await chrome.storage.session.remove('sessionKeys');
        await showView('locked');
    }
}


async function showView(viewName) {
    lockedView.classList.add('hidden');
    unlockedView.classList.add('hidden');

    if (viewName === 'unlocked') {
        unlockedView.classList.remove('hidden');
        await loadAndRenderActiveChat();
    } else if (viewName === 'locked') {
        lockedView.classList.remove('hidden');
        unlockStatus.textContent = "Enter your password to decrypt API keys for this session.";
        unlockStatus.className = 'card-description';
        unlockBtn.disabled = false;
        passwordInput.disabled = false;
        passwordInput.value = '';
        
        const storedData = await chrome.storage.session.get([LOCKOUT_END_TIME_KEY]);
        const lockoutEndTime = storedData[LOCKOUT_END_TIME_KEY];
        const currentTime = Date.now();

        if (lockoutEndTime && lockoutEndTime > currentTime) {
            unlockBtn.disabled = true;
            passwordInput.disabled = true;
            const remainingTime = Math.ceil((lockoutEndTime - currentTime) / 1000);
            unlockStatus.textContent = `Too many failed attempts. Try again in ${remainingTime} seconds.`;
            unlockStatus.className = 'status-error';

            const timer = setInterval(() => {
                const updatedRemainingTime = Math.ceil((lockoutEndTime - Date.now()) / 1000);
                if (updatedRemainingTime <= 0) {
                    clearInterval(timer);
                    showView('unlocked');
                } else {
                    unlockStatus.textContent = `Too many failed attempts. Try again in ${updatedRemainingTime} seconds.`;
                }
            }, 1000);
        }
        
    } else if (viewName === 'no_keys') {
        lockedView.classList.remove('hidden');
        unlockStatus.textContent = "API Keys not set. Go to Options to sync or set manually.";
        unlockStatus.className = 'status-error';
        unlockBtn.disabled = true;
        passwordInput.disabled = true;
        passwordInput.value = '';
    }
}

function renderChatHistory() {
    chatContainer.innerHTML = '';
    if (aiHistory && aiHistory.length > 0) {
        aiHistory.forEach(msg => {
            if (msg.role && msg.parts && msg.parts[0].text) {
                addMessageToChat(msg.role, msg.parts[0].text, false, true);
            }
        });
    } else {
        aiHistory = [];
        addMessageToChat('model', "MDAA session unlocked. How can I help?");
    }
}

async function loadAndRenderActiveChat() {
    const data = await storageArea().get(chatHistoryKey());
    const history = data[chatHistoryKey()];
    
    if (history && history.length > 0) {
        aiHistory = history;
    } else {
        aiHistory = [];
    }
    renderChatHistory();
}

async function handleContextData() {
    const data = await chrome.storage.session.get('contextData');
    if (data.contextData) {
        const { source, action, selectionText, linkUrl } = data.contextData;

        if (source === 'contextMenuSelection' && action === 'smartAnalyze') {
            const trimmedText = selectionText.trim();
            const iocRegex = /^(\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-fA-F0-9]{32,128}|[\w.-]+\.[\w.-]+)$/i; 
            
            if (iocRegex.test(trimmedText) && !trimmedText.includes(' ') && trimmedText.length <= 200) {
                activateTab('tab-quick-check');
                iocInput.value = trimmedText;
            } else {
                activateTab('tab-chat');
                chatInput.value = selectionText;
            }
        } else if (source === 'contextMenuPage') {
            activateTab('tab-page-analysis');
        } else if (source === 'contextMenuLink' && action === 'analyzeLink') {
            activateTab('tab-quick-check');
            iocInput.value = linkUrl;
        }
        await chrome.storage.session.remove('contextData');
    }
}

async function handleUnlock() {

    const password = passwordInput.value;
    if (!password) {
        unlockStatus.textContent = "Password cannot be empty.";
        unlockStatus.className = 'status-error';
        return;
    }
    
    const storedData = await chrome.storage.session.get([FAILED_ATTEMPTS_KEY, LOCKOUT_END_TIME_KEY]);
    let failedAttempts = storedData[FAILED_ATTEMPTS_KEY] || 0;
    const lockoutEndTime = storedData[LOCKOUT_END_TIME_KEY] || 0;
    const currentTime = Date.now();

    if (lockoutEndTime > currentTime) {
        const remainingTime = Math.ceil((lockoutEndTime - currentTime) / 1000);
        unlockStatus.textContent = `Too many failed attempts. Try again in ${remainingTime} seconds.`;
        unlockStatus.className = 'status-error';
        return;
    }

    unlockStatus.textContent = "Decrypting...";
    unlockStatus.className = '';
    unlockBtn.disabled = true;

    try {
        const data = await chrome.storage.local.get(API_KEYS_NAME);
        if (!data[API_KEYS_NAME]) {
            showView('no_keys');
            return;
        }

        const decryptedKeysJSON = await CryptoHelper.decrypt(data[API_KEYS_NAME], password);

        if (decryptedKeysJSON) {
            
            const keys = JSON.parse(decryptedKeysJSON);
            
            if (!validateSessionKeys(keys)) {
                 throw new Error("Decrypted data is structurally invalid.");
            }
            
            sessionKeys = keys;
            await chrome.storage.session.set({ sessionKeys: sessionKeys });
            
            await chrome.storage.session.remove([FAILED_ATTEMPTS_KEY, LOCKOUT_END_TIME_KEY]);
            
            await showView('unlocked');
        } else {
            
            failedAttempts++;
            let delay = 0;
            if (failedAttempts >= MAX_ATTEMPTS_BEFORE_DELAY) {
                const policyKey = failedAttempts >= 6 ? 6 : failedAttempts;
                delay = LOCKOUT_POLICY[policyKey] || 0;
            }
            
            const newLockoutEndTime = delay > 0 ? currentTime + delay : 0;
            const updateData = { [FAILED_ATTEMPTS_KEY]: failedAttempts };
            if (newLockoutEndTime > 0) {
                updateData[LOCKOUT_END_TIME_KEY] = newLockoutEndTime;
            } else {
                await chrome.storage.session.remove(LOCKOUT_END_TIME_KEY);
            }
            await chrome.storage.session.set(updateData);

            unlockStatus.textContent = "Decryption failed. Wrong password?";
            unlockStatus.className = 'status-error';
            unlockBtn.disabled = false;
            
            if (delay > 0) {
                showView('locked');
            }
        }
    } catch (e) {
        console.error("Unlock error:", e);
        const isValidationFailure = e.message && e.message.includes("structurally invalid");
        unlockStatus.textContent = isValidationFailure ? "Error: Invalid data structure in storage." : "An error occurred during decryption.";
        unlockStatus.className = 'status-error';
        unlockBtn.disabled = false;
    }
}

function handleTabClick(e) {
  
    const tabId = e.target.dataset.tab;
    activateTab(tabId);
}
function activateTab(tabId) {

    tabs.forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabId);
    });
    tabContents.forEach(content => {
        content.classList.toggle('active', content.id === tabId);
        content.classList.toggle('hidden', content.id !== tabId);
    });
}

async function handleSendChat() {
    const userText = chatInput.value.trim();
    if (!userText || !sessionKeys?.gemini) {
        addMessageToChat('model', "Error: Gemini API key is missing or session is locked.");
        return;
    }

    chatInput.value = "";
    sendChatBtn.disabled = true;
    chatInput.disabled = true;

    addMessageToChat('user', userText);

    addMessageToChat('model', "Thinking...", true);

    try {
        const historyToSend = aiHistory.length > CHAT_HISTORY_WINDOW_SIZE 
            ? aiHistory.slice(-CHAT_HISTORY_WINDOW_SIZE) 
            : aiHistory;

        const response = await callGeminiAPI(sessionKeys.gemini, historyToSend);

        const thinkingEl = chatContainer.querySelector('.thinking');
        if (thinkingEl) thinkingEl.remove();

        if (response.error) {
            let errorMsg = `Error: ${response.error}`;
            if (response.error.includes("Invalid API Key")) {
                errorMsg += ` <a href="#" class="inline-options-link">Go to Options</a>`;
            }
            addMessageToChat('model', errorMsg);
        } else {
            addMessageToChat('model', response.text);
        }
    } catch (e) {
        const thinkingEl = chatContainer.querySelector('.thinking');
        if (thinkingEl) thinkingEl.remove();
        addMessageToChat('model', `Error: ${e.message}`);
    } finally {
        sendChatBtn.disabled = false;
        chatInput.disabled = false;
        chatInput.focus();
        chatContainer.querySelectorAll('.inline-options-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                chrome.runtime.openOptionsPage();
            });
        });
    }
}

function renderTables(text) {

    return text.replace(/((?:\|.*\|\r?\n)+)/g, (match) => {
        const rows = match.trim().split('\n');
        let html = '<table>';
        
        const header = rows[0].split('|').filter(h => h.trim()).map(h => h.trim());
        html += '<thead><tr>';
        header.forEach(h => html += `<th>${h}</th>`);
        html += '</tr></thead>';

        if (rows.length > 1 && rows[1].includes('---')) {
            html += '<tbody>';
            rows.slice(2).forEach(rowStr => {
                const cells = rowStr.split('|').filter(c => c.trim()).map(c => c.trim());
                html += '<tr>';
                cells.forEach(c => html += `<td>${c}</td>`);
                html += '</tr>';
            });
            html += '</tbody>';
        } else {
             html += '<tbody>';
             rows.slice(1).forEach(rowStr => {
                const cells = rowStr.split('|').map(c => c.trim());
                html += '<tr>';
                cells.forEach(c => html += `<td>${c}</td>`);
                html += '</tr>';
            });
            html += '</tbody>';
        }
        
        html += '</table>';
        return html;
    });
}

async function saveActiveChat() {
    await storageArea().set({ [chatHistoryKey()]: aiHistory });
}

function addMessageToChat(role, text, isThinking = false, isBatchRender = false) {
    const messageEl = document.createElement('div');
    messageEl.className = `message-bubble ${role}-message`;

    if (isThinking) {
        messageEl.classList.add('thinking');
        messageEl.innerHTML = `<div class="ai-thinking-dot"></div><div class="ai-thinking-dot"></div><div class="ai-thinking-dot"></div>`;
    } else if (role === 'model') {
        let htmlContent = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        htmlContent = htmlContent.replace(/```([\s\S]*?)```/g, (match, code) => {
            const unescapedCode = code.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
            return `<pre class="code-block"><code>${unescapedCode.trim()}</code></pre>`;
        });

        const parts = htmlContent.split(/(<pre.*?>[\s\S]*?<\/pre>)/g);
        
        const processedParts = parts.map(part => {
            if (part.startsWith('<pre')) {
                return part;
            }
            
            let processedPart = renderTables(part);

            return processedPart
                .replace(/`([^`]+?)`/g, '<code>$1</code>')
                .replace(/\*\*([^\*]+?)\*\*/g, '<strong>$1</strong>')
                .replace(/^\s*[\*\-] (.*)$/gm, '<span class="bullet-point">$1</span>')
                .replace(/^## (.*)$/gm, '<h3 class="chat-heading">$1</h3>')
                .replace(/\n/g, '<br>');
        });

        messageEl.innerHTML = processedParts.join('');

    } else {
        messageEl.textContent = text;
    }

    if (role === 'model' && !isThinking) {
        const copyBtn = document.createElement('button');
        copyBtn.textContent = 'Copy';
        copyBtn.className = 'copy-btn';
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(text);
            copyBtn.textContent = 'Copied!';
            copyBtn.classList.add('copied');
            setTimeout(() => {
                copyBtn.textContent = 'Copy';
                copyBtn.classList.remove('copied');
            }, 1500);
        });
        messageEl.appendChild(copyBtn);
    }
    
    chatContainer.appendChild(messageEl);

    if (!isBatchRender) {
        aiHistory.push({ role: role, parts: [{ text: text }] });
        if (!isThinking) {
            saveActiveChat();
        }
    }
    
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

async function handleQcAiAnalyze() {

    const resultsText = quickCheckResults.innerText;
    if (!resultsText || resultsText.includes("Analyzing IoC...")) {
        addMessageToChat('model', "Error: No Quick Check results to analyze.");
        return;
    }
    
    const prompt = `Please summarize the key takeaways from the following IoC analysis results:\n\n"""\n${resultsText}\n"""`;
    
    activateTab('tab-chat');
    chatInput.value = prompt;
    await handleSendChat();
}

async function handleSmartCheck() {

    const iocList = iocInput.value.trim().split('\n').filter(ioc => ioc.trim() !== '');
    qcAiAnalyzeGroup.classList.add('hidden');

    if (iocList.length === 0) {
        quickCheckResults.innerHTML = `<p class="status-error">IoC input is empty.</p>`;
        return;
    }
    if (!sessionKeys || (!sessionKeys.virustotal && !sessionKeys.abuseipdb && !sessionKeys.shodan)) {
        quickCheckResults.innerHTML = `<p class="status-error">API Keys not loaded or session is locked. At least one key (VT, AbuseIPDB, or Shodan) is required for checks.</p>`;
        return;
    }

    smartCheckBtn.disabled = true;
    iocInput.disabled = true;
    quickCheckResults.innerHTML = `<p>Analyzing ${iocList.length} IoC(s)...</p>`;
    let combinedHtml = "";

    try {
        for (const ioc of iocList) {
            let type = 'hash';
            if (ioc.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)) type = 'ipv4';
            else if (ioc.startsWith('http') || ioc.startsWith('www.')) type = 'url';
            else if (ioc.includes('.')) type = 'domain';

            let html = `<h4>IoC Analysis: ${ioc}</h4>`;
            
            if (type === 'ipv4') {
                const hasVT = sessionKeys.virustotal;
                const hasAbuse = sessionKeys.abuseipdb;
                const hasShodan = sessionKeys.shodan;

                if (!hasVT && !hasAbuse && !hasShodan) {
                    html += `<p class="status-error">No required IP check API keys (VT, AbuseIPDB, Shodan) are set.</p>`;
                    combinedHtml += `<div class="quick-check-result">${html}</div>`;
                    continue;
                }
                
                const promises = [];
                
           
                promises.push(hasVT ? getVTResponse(sessionKeys.virustotal, ioc, type) : Promise.resolve({ error: "VT key not set." }));
                
                promises.push(hasAbuse ? checkAbuseIPDB(sessionKeys.abuseipdb, ioc) : Promise.resolve({ error: "AbuseIPDB key not set." }));
                
                promises.push(hasShodan ? checkShodan(sessionKeys.shodan, ioc) : Promise.resolve({ error: "Shodan key not set." }));

                const [vtResult, abuseResult, shodanResult] = await Promise.all(promises);

                html += `<div class="quick-check-result">`;
                html += `<p class="qc-title">VirusTotal</p>`;
                if (vtResult.error && vtResult.error !== "VT key not set.") {
                    html += `<p class="status-error">${vtResult.error}</p>`;
                } else if (vtResult.error) {
                     html += `<p class="status-error">${vtResult.error}</p>`;
                } else {
                    html += `<p><span class="qc-label">Malicious:</span> <span class="qc-malicious">${vtResult.stats.malicious} / ${vtResult.stats.total}</span></p>`;
                    html += `<p><span class="qc-label">Suspicious:</span> <span class="qc-suspicious">${vtResult.stats.suspicious} / ${vtResult.stats.total}</span></p>`;
                }
                html += `</div>`;

                html += `<div class="quick-check-result">`;
                html += `<p class="qc-title">AbuseIPDB</p>`;
                if (abuseResult.error && abuseResult.error !== "AbuseIPDB key not set.") {
                    html += `<p class="status-error">${abuseResult.error}</p>`;
                } else if (abuseResult.error) {
                    html += `<p class="status-error">${abuseResult.error}</p>`;
                } else {
                    html += `<p><span class="qc-label">Score:</span> <span class="qc-malicious">${abuseResult.score}%</span></p>`;
                    html += `<p><span class="qc-label">Reports:</span> <span class="qc-value">${abuseResult.totalReports}</span></p>`;
                    html += `<p><span class="qc-label">Domain:</span> <span class="qc-value">${abuseResult.domain || 'N/A'}</span></p>`;
                }
                html += `</div>`;
                
                html += `<div class="quick-check-result">`;
                html += `<p class="qc-title">Shodan</p>`;
                if (shodanResult.error && shodanResult.error !== "Shodan key not set.") {
                    html += `<p class="status-error">${shodanResult.error}</p>`;
                } else if (shodanResult.error) {
                    html += `<p class="status-error">${shodanResult.error}</p>`;
                } else {
                    html += `<p><span class="qc-label">OS:</span> <span class="qc-value">${shodanResult.os}</span></p>`;
                    html += `<p><span class="qc-label">ISP:</span> <span class="qc-value">${shodanResult.isp}</span></p>`;
                    html += `<p><span class="qc-label">Ports:</span> <span class="qc-value">${shodanResult.ports.join(', ') || 'None'}</span></p>`;
                }
                html += `</div>`;
                combinedHtml += html;

            } 
            else if (type === 'url' || type === 'domain' || type === 'hash') {
                if (!sessionKeys.virustotal) {
                    html += `<p class="status-error">VirusTotal API Key is required for this check.</p>`;
                    combinedHtml += `<div class="quick-check-result">${html}</div>`;
                    continue;
                }
                
                const result = await getVTResponse(sessionKeys.virustotal, ioc, type);

                html += `<div class="quick-check-result">`;
                html += `<p class="qc-title">VirusTotal (${type})</p>`;
                if (result.error) {
                    html += `<p class="status-error">${result.error}</p>`;
                } else {
                    html += `<p><span class="qc-label">Malicious:</span> <span class="qc-malicious">${result.stats.malicious} / ${result.stats.total}</span></p>`;
                    html += `<p><span class="qc-label">Suspicious:</span> <span class="qc-suspicious">${result.stats.suspicious} / ${result.stats.total}</span></p>`;
                }
                html += `</div>`;
                combinedHtml += html;
            }
        }
        quickCheckResults.innerHTML = combinedHtml;
        if (iocList.length > 0) {
            qcAiAnalyzeGroup.classList.remove('hidden');
        }
    } catch (e) {
        quickCheckResults.innerHTML += `<p class="status-error">An unexpected error occurred: ${e.message}</p>`;
    } finally {
        smartCheckBtn.disabled = false;
        iocInput.disabled = false;
    }
}

const getPageContentFunc = () => {

    let mainContent = null;
    try {
        const selectors = [
            'article', 
            '[role="main"]', 
            '#main', 
            '#content',
            '.main', 
            '.content',
            '.post-body',
            '.article-content'
        ];
        
        for (const selector of selectors) {
            const el = document.querySelector(selector);
            if (el && el.textContent.length > 200) {
                mainContent = el.textContent;
                break;
            }
        }
        if (!mainContent) {
            mainContent = document.body.textContent;
        }
    } catch (e) {
        mainContent = document.body.textContent;
    }
    return mainContent;
};

async function handlePageAnalysis(action) {

    if (!sessionKeys) {
        activateTab('tab-chat');
        addMessageToChat('model', "Error: Session is locked. Please unlock to analyze the page.");
        return;
    }

    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });

    if (!tab || tab.url.startsWith("chrome://")) {
        activateTab('tab-chat');
        addMessageToChat('model', "Error: Cannot analyze this page (e.g., 'chrome://' URLs).");
        return;
    }

    summarizePageBtn.disabled = true;
    extractBtn.disabled = true;

    try {
        let pageContent = "";
        let prompt = "";
        let sourceText = "page";
        
        try {
            const selectionResults = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => window.getSelection().toString()
            });
            if (selectionResults && selectionResults[0] && selectionResults[0].result) {
                pageContent = selectionResults[0].result;
                sourceText = "selection";
            }
        } catch (e) {
                 console.log("Could not get selection, falling back to body.");
        }

        if (!pageContent) {
            sourceText = "page (reader mode)";
            const bodyResults = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: getPageContentFunc
            });
            if (bodyResults && bodyResults[0] && bodyResults[0].result) {
                pageContent = bodyResults[0].result;
            }
        }
        
        if (!pageContent) {
            addMessageToChat('model', "Error: Page content is empty or could not be read.");
            return;
        }

        const truncatedContent = pageContent.substring(0, MAX_PAGE_CONTENT_LENGTH);
        if (pageContent.length > truncatedContent.length) {
            sourceText = `truncated ${sourceText}`;
        }

        if (action === 'summarize') {
            prompt = `Please summarize the key security-related takeaways from the following text (from ${sourceText}):\n\n"""\n${truncatedContent}...\n"""`;
        } else if (action === 'extract_iocs') {
            prompt = `Extract all Indicators of Compromise (IoCs) from the following text (from ${sourceText}) and present them as a clean, categorized list (e.g., Hashes, Domains, IPs):\n\n"""\n${truncatedContent}\n"""`;
        }

        activateTab('tab-chat');
        chatInput.value = prompt;
        await handleSendChat();

    } catch (e) {
        console.error("Page analysis error:", e);
        activateTab('tab-chat');
        if (e.message.includes("Cannot access")) {
             addMessageToChat('model', "Error: Cannot access this page. This page may be protected (like the Chrome Web Store).");
        } else {
             addMessageToChat('model', `Error: Could not access page content. ${e.message}`);
        }
    } finally {
        summarizePageBtn.disabled = false;
        extractBtn.disabled = false;
    }
}


function showChatView() {
    historyView.classList.add('hidden');
    chatView.classList.remove('hidden');
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

async function showHistoryView() {
    chatView.classList.add('hidden');
    historyView.classList.remove('hidden');
    await loadHistoryArchive();
}

async function saveCurrentChatToHistory() {
    if (aiHistory.length <= 1) return;

    const data = await chrome.storage.local.get(ALL_SESSIONS_KEY);
    const allSessions = data[ALL_SESSIONS_KEY] || [];

    const firstUserMsg = aiHistory.find(m => m.role === 'user');
    const title = firstUserMsg ? firstUserMsg.parts[0].text.substring(0, 40) + '...' : 'Chat Session';
    
    const newSession = {
        id: `session_${Date.now()}`,
        title: title,
        timestamp: Date.now(),
        history: aiHistory
    };

    allSessions.unshift(newSession);
    await chrome.storage.local.set({ [ALL_SESSIONS_KEY]: allSessions });
}

async function handleNewChat() {
    await saveCurrentChatToHistory();
    aiHistory = [];
    await storageArea().remove(chatHistoryKey());
    renderChatHistory();
}

async function loadHistoryArchive() {
    historyListContainer.innerHTML = '<p>Loading history...</p>';
    const data = await chrome.storage.local.get(ALL_SESSIONS_KEY);
    const allSessions = data[ALL_SESSIONS_KEY] || [];

    if (allSessions.length === 0) {
        historyListContainer.innerHTML = '<p>No saved chat history.</p>';
        return;
    }

    historyListContainer.innerHTML = '';
    allSessions.forEach(session => {
        const item = document.createElement('div');
        item.className = 'history-item';

        const title = document.createElement('span');
        title.className = 'history-item-title';
        title.textContent = session.title;

        const date = document.createElement('span');
        date.className = 'history-item-date';
        date.textContent = new Date(session.timestamp).toLocaleDateString();

        const actions = document.createElement('div');
        actions.className = 'history-item-actions';
        
        const loadBtn = document.createElement('button');
        loadBtn.textContent = 'Load';
        loadBtn.className = 'history-load-btn';
        loadBtn.dataset.sessionId = session.id;
        loadBtn.addEventListener('click', () => handleLoadSession(session.id));

        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Delete';
        deleteBtn.className = 'history-delete-btn';
        deleteBtn.dataset.sessionId = session.id;
        deleteBtn.addEventListener('click', () => handleDeleteSession(session.id));

        actions.appendChild(loadBtn);
        actions.appendChild(deleteBtn);
        
        item.appendChild(title);
        item.appendChild(date);
        item.appendChild(actions);
        historyListContainer.appendChild(item);
    });
}

async function handleLoadSession(sessionId) {
    const data = await chrome.storage.local.get(ALL_SESSIONS_KEY);
    const allSessions = data[ALL_SESSIONS_KEY] || [];
    const sessionToLoad = allSessions.find(s => s.id === sessionId);

    if (sessionToLoad) {
        await saveCurrentChatToHistory();
        
        aiHistory = sessionToLoad.history;
        await saveActiveChat();
        renderChatHistory();
        showChatView();
    }
}

async function handleDeleteSession(sessionId) {
    const data = await chrome.storage.local.get(ALL_SESSIONS_KEY);
    let allSessions = data[ALL_SESSIONS_KEY] || [];
    allSessions = allSessions.filter(s => s.id !== sessionId);
    await chrome.storage.local.set({ [ALL_SESSIONS_KEY]: allSessions });
    await loadHistoryArchive();
}