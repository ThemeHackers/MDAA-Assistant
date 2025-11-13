const CONTEXT_MENU_ID_SMART_ANALYZE = "MDAA_SMART_ANALYZE";
const CONTEXT_MENU_ID_PAGE_ANALYSIS = "MDAA_PAGE_ANALYSIS";
const CONTEXT_MENU_ID_ANALYZE_LINK = "MDAA_ANALYZE_LINK";
const API_KEYS_NAME = "_mdaa_api_keys_v1_ext";
const TEMP_KEYS_SESSION = "_mdaa_temp_keys_ext"; 
const SESSION_KEYS = "sessionKeys"; 

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: CONTEXT_MENU_ID_SMART_ANALYZE, title: "Analyze '%s' with MDAA", contexts: ["selection"] });
  chrome.contextMenus.create({ id: CONTEXT_MENU_ID_PAGE_ANALYSIS, title: "Analyze this page with MDAA", contexts: ["page"] });
  chrome.contextMenus.create({ id: CONTEXT_MENU_ID_ANALYZE_LINK, title: "Analyze link with MDAA", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let contextData = {};
  if (info.menuItemId === CONTEXT_MENU_ID_SMART_ANALYZE) contextData = { source: 'contextMenuSelection', action: 'smartAnalyze', selectionText: info.selectionText };
  else if (info.menuItemId === CONTEXT_MENU_ID_PAGE_ANALYSIS) contextData = { source: 'contextMenuPage', action: 'pageAnalysis' };
  else if (info.menuItemId === CONTEXT_MENU_ID_ANALYZE_LINK) contextData = { source: 'contextMenuLink', action: 'analyzeLink', linkUrl: info.linkUrl };
  
  await chrome.storage.session.set({ contextData: contextData });
  chrome.action.openPopup();
});


chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {

    if (sender.url && sender.url.startsWith("https://dashsecurity.netlify.app") && message.type === "SYNC_ENCRYPTED_BLOB" && message.data) {
        console.log("Received newly encrypted keys blob from content script.");

        (async () => {
            try {
          
                await chrome.storage.local.set({ [API_KEYS_NAME]: message.data });
                

                await chrome.storage.session.remove(SESSION_KEYS); 
                
                console.log("Encrypted keys blob saved to storage.local. Session keys cleared.");
                sendResponse({ status: "success", message: "Keys saved. You can close this tab." });
              

                chrome.runtime.openOptionsPage();

            } catch (error) {
                console.error("Error saving encrypted blob:", error);
                sendResponse({ status: "error", message: "Background script failed to save keys." });
            }
        })();
        
        return true; 
    }

    return false; 
});
