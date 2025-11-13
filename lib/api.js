let spec = null;
const REQUEST_TIMEOUT = 20000;

function urlToBase64(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function getSpec() {
    if (spec) return spec;
    try {
        const specURL = chrome.runtime.getURL('mdaaspec.json');
        const response = await fetch(specURL);
        if (!response.ok) throw new Error("Failed to load mdaaspec.json");
        spec = await response.json();
        return spec;
    } catch (error) {
        console.error("Error loading spec:", error);
        return null;
    }
}

export async function callGeminiAPI(apiKey, history, systemPromptOverride = null) {
    const model = "gemini-2.5-flash";
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    const appSpec = await getSpec();
    if (!appSpec) return { error: "Could not load AI model specifications." };

    const payload = {
        contents: history,
        systemInstruction: {
            parts: [{
                text: systemPromptOverride || JSON.stringify(appSpec.gemInstructions)
            }]
        }
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
        const response = await fetch(apiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401 || response.status === 403) {
            return { error: `Gemini API Error: Invalid API Key. Please check Options.` };
        }
        if (response.status === 429) {
            return { error: `Gemini API Error: Rate limit exceeded. Please wait.` };
        }

        if (!response.ok) {
            const errorData = await response.json();
            return { error: `API Error: ${errorData.error.message}` };
        }

        const result = await response.json();
        const text = result.candidates?.[0]?.content?.parts?.[0]?.text;

        if (text) {
            return { text };
        }
        return { error: "No response text from AI." };

    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            return { error: "Connection Error: Request timed out." };
        }
        console.error(error);
        return { error: "Connection Error: Failed to reach the AI model." };
    }
}

export async function getVTResponse(apiKey, ioc, type) {
    if (!apiKey) {
        return { error: "VT API Key is missing." };
    }
    const iocType = type.toLowerCase();
    let endpoint = '';

    if (iocType.includes('hash') || iocType === 'md5' || iocType === 'sha1' || iocType === 'sha256') {
        endpoint = `files/${ioc}`;
    } else if (iocType === 'ipv4') {
        endpoint = `ip_addresses/${ioc}`;
    } else if (iocType === 'domain') {
        endpoint = `domains/${ioc}`;
    } else if (iocType === 'url') {
        const urlId = urlToBase64(ioc);
        endpoint = `urls/${urlId}`;
    } else {
        return { error: `Unsupported IoC type for VirusTotal: ${type}` };
    }

    const apiUrl = `https://www.virustotal.com/api/v3/${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: { 'x-apikey': apiKey },
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401 || response.status === 403) {
            return { error: `VT API Error: Invalid API Key. Please check Options.` };
        }
        if (response.status === 429) {
            return { error: `VT API Error: Rate limit exceeded. Please wait.` };
        }
        if (response.status === 404 && iocType === 'url') {
             return { error: `VT API Error: URL not found. It may need to be scanned first.` };
        }
        if (!response.ok) {
            try {
                const errorData = await response.json();
                return { error: `VT API Error (${response.status}): ${errorData.error?.message || response.statusText}` };
            } catch (jsonError) {
                return { error: `VT API Error (${response.status}): Failed to parse error response.` };
            }
        }

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats || {};
        return {
            ioc: ioc,
            stats: {
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                total: (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0)
            }
        };
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            return { error: "VT connection error: Request timed out." };
        }

        return { error: `VT connection error: ${error.message}` };
    }
}

export async function checkAbuseIPDB(apiKey, ip) {
    if (!apiKey) {
        return { error: "AbuseIPDB key is missing." };
    }
    if (!ip.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)) {
        return { error: "This is not a valid IP address." };
    }

    const apiUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Key': apiKey,
                'Accept': 'application/json'
            },
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401 || response.status === 403) {
            return { error: `AbuseIPDB Error: Invalid API Key. Please check Options.` };
        }
        if (response.status === 429) {
            return { error: `AbuseIPDB Error: Rate limit exceeded. Please wait.` };
        }
        if (!response.ok) {

             try {
                const errorData = await response.json();
                return { error: `AbuseIPDB Error (${response.status}): ${errorData.errors[0].detail || response.statusText}` };
            } catch (jsonError) {
                return { error: `AbuseIPDB Error (${response.status}): Failed to parse error response.` };
            }
        }

        const data = await response.json();
        return {
            ip: data.data.ipAddress,
            score: data.data.abuseConfidenceScore,
            domain: data.data.domain,
            totalReports: data.data.totalReports
        };
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            return { error: "AbuseIPDB connection error: Request timed out." };
        }

        return { error: `AbuseIPDB connection error: ${error.message}` };
    }
}

export async function checkShodan(apiKey, ip) {
    if (!apiKey) {
        return { error: "Shodan key not set." };
    }
    if (!ip.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)) {
        return { error: "Not a valid IP for Shodan." };
    }

    const apiUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401 || response.status === 403) {
            return { error: `Shodan Error: Invalid API Key. Please check Options.` };
        }
        if (response.status === 429) {
            return { error: `Shodan Error: Rate limit exceeded. Please wait.` };
        }
        if (response.status === 404) {
             
             return { error: "Host not found in Shodan." };
        }
        if (!response.ok) {

            try {
                const errorData = await response.json();
                 return { error: `Shodan Error (${response.status}): ${errorData.error || response.statusText}` };
            } catch (jsonError) {
                return { error: `Shodan Error (${response.status}): Could not fetch data.` };
            }
        }

        const data = await response.json();
        return {
            ip: data.ip_str,
            ports: data.ports || [],
            os: data.os || "N/A",
            isp: data.isp || "N/A"
        };
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            return { error: "Shodan connection error: Request timed out." };
        }

        return { error: `Shodan connection error: ${error.message}` };
    }
}
