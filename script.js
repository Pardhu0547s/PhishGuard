const API_URL = window.location.origin;

// ===============================
// ELEMENTS
// ===============================

const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const resultCard = document.getElementById("resultCard");
const resultIcon = document.getElementById("resultIcon");
const resultTitle = document.getElementById("resultTitle");
const resultURL = document.getElementById("resultURL");

const legitimateProbability = document.getElementById(
    "legitimateProbability"
);

const phishingProbability = document.getElementById(
    "phishingProbability"
);

const resultMessage = document.getElementById("resultMessage");

const analysisItems = document.querySelectorAll(".analysis-item");

// Domain Intelligence
const domainIntelligence = document.getElementById("domainIntelligence");

const infoHostname = document.getElementById("infoHostname");
const infoURLLength = document.getElementById("infoURLLength");
const infoPathLength = document.getElementById("infoPathLength");
const infoQueryLength = document.getElementById("infoQueryLength");
const infoSubdomains = document.getElementById("infoSubdomains");

const infoDNS = document.getElementById("infoDNS");
const infoMX = document.getElementById("infoMX");
const infoTXT = document.getElementById("infoTXT");
const infoNS = document.getElementById("infoNS");
const infoIPCount = document.getElementById("infoIPCount");
const infoCNAME = document.getElementById("infoCNAME");

const infoDomainAge = document.getElementById("infoDomainAge");
const infoRecentDomain = document.getElementById("infoRecentDomain");
const infoRegistrar = document.getElementById("infoRegistrar");
const infoNameServers = document.getElementById("infoNameServers");
const infoPrivacy = document.getElementById("infoPrivacy");

// History
const historySection = document.getElementById("historySection");
const historyList = document.getElementById("historyList");
const clearHistoryButton = document.getElementById("clearHistoryButton");


// ===============================
// SHOW RESULT SECTIONS
// ===============================

function showResultSections() {

    if (resultCard) {
        resultCard.style.setProperty(
            "display",
            "block",
            "important"
        );
    }

    if (domainIntelligence) {
        domainIntelligence.style.setProperty(
            "display",
            "block",
            "important"
        );
    }

    if (historySection) {
        historySection.style.setProperty(
            "display",
            "block",
            "important"
        );
    }
}


// ===============================
// SCROLL TO RESULT
// ===============================

function scrollToResult() {

    if (!resultCard) return;

    setTimeout(() => {

        resultCard.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }, 100);
}


// ===============================
// SECURITY ANALYSIS
// ===============================

function resetSecurityAnalysis() {

    analysisItems.forEach((item) => {

        const icon =
            item.querySelector(".analysis-icon");

        if (icon) {

            icon.textContent = "•";
            icon.style.color = "";
            icon.style.background = "";
        }

        item.classList.remove(
            "analysis-good",
            "analysis-warning",
            "analysis-danger"
        );
    });
}


function setAnalysisStatus(index, status) {

    if (!analysisItems[index]) return;

    const item = analysisItems[index];

    const icon =
        item.querySelector(".analysis-icon");

    if (!icon) return;

    let value = status;

    if (typeof value === "string") {

        value = value.toLowerCase();

        if (
            value === "true" ||
            value === "yes" ||
            value === "safe" ||
            value === "good" ||
            value === "legitimate" ||
            value === "1"
        ) {

            value = true;

        } else if (
            value === "false" ||
            value === "no" ||
            value === "danger" ||
            value === "phishing" ||
            value === "0"
        ) {

            value = false;
        }
    }


    if (value === true || value === 1) {

        icon.textContent = "✓";
        icon.style.color = "#22c55e";
        icon.style.background =
            "rgba(34,197,94,0.10)";

        item.classList.add(
            "analysis-good"
        );

    } else if (
        value === false ||
        value === 0
    ) {

        icon.textContent = "×";
        icon.style.color = "#ef4444";
        icon.style.background =
            "rgba(239,68,68,0.10)";

        item.classList.add(
            "analysis-danger"
        );

    } else {

        icon.textContent = "•";
        icon.style.color = "#64748b";
        icon.style.background =
            "rgba(100,116,139,0.10)";
    }
}


function updateSecurityAnalysis(data) {

    resetSecurityAnalysis();

    const analysis =
        data.security_analysis || {};

    setAnalysisStatus(
        0,
        analysis.url_structure
    );

    setAnalysisStatus(
        1,
        analysis.domain_structure
    );

    setAnalysisStatus(
        2,
        analysis.https_usage
    );

    setAnalysisStatus(
        3,
        analysis.suspicious_keywords
    );

    setAnalysisStatus(
        4,
        analysis.dns_intelligence
    );

    setAnalysisStatus(
        5,
        analysis.whois_information
    );
}


// ===============================
// VALUE HELPERS
// ===============================

function setValue(
    element,
    value,
    suffix = ""
) {

    if (!element) return;

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        element.textContent = "--";
        return;
    }

    element.textContent =
        `${value}${suffix}`;
}


// ===============================
// BOOLEAN VALUE HELPER
// ===============================

function setBooleanValue(
    element,
    value
) {

    if (!element) return;

    // No value
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        element.textContent = "--";
        return;
    }

    // Backend can return text values
    if (typeof value === "string") {

        const text =
            value.trim().toLowerCase();

        // Unknown
        if (text === "unknown") {

            element.textContent =
                "UNKNOWN";

            return;
        }

        // Unavailable
        if (text === "unavailable") {

            element.textContent =
                "UNAVAILABLE";

            return;
        }

        // YES
        if (
            text === "yes" ||
            text === "true" ||
            text === "1"
        ) {

            element.textContent =
                "YES";

            return;
        }

        // NO
        if (
            text === "no" ||
            text === "false" ||
            text === "0"
        ) {

            element.textContent =
                "NO";

            return;
        }
    }

    // Boolean / numeric values
    if (
        value === true ||
        value === 1
    ) {

        element.textContent =
            "YES";

    } else if (
        value === false ||
        value === 0
    ) {

        element.textContent =
            "NO";

    } else {

        element.textContent =
            String(value);
    }
}


// ===============================
// RESET DOMAIN INTELLIGENCE
// ===============================

function resetDomainIntelligence() {

    setValue(
        infoHostname,
        null
    );

    setValue(
        infoURLLength,
        null
    );

    setValue(
        infoPathLength,
        null
    );

    setValue(
        infoQueryLength,
        null
    );

    setValue(
        infoSubdomains,
        null
    );

    setBooleanValue(
        infoDNS,
        null
    );

    setBooleanValue(
        infoMX,
        null
    );

    setBooleanValue(
        infoTXT,
        null
    );

    setBooleanValue(
        infoNS,
        null
    );

    setValue(
        infoIPCount,
        null
    );

    setValue(
        infoCNAME,
        null
    );

    setValue(
        infoDomainAge,
        null
    );

    setBooleanValue(
        infoRecentDomain,
        null
    );

    setBooleanValue(
        infoRegistrar,
        null
    );

    setValue(
        infoNameServers,
        null
    );

    setBooleanValue(
        infoPrivacy,
        null
    );
}


// ===============================
// URL INFORMATION
// ===============================

function getURLInformation(url) {

    try {

        const parsed =
            new URL(url);

        const hostname =
            parsed.hostname;

        const hostnameParts =
            hostname.split(".")
                .filter(Boolean);

        let subdomains = 0;

        if (hostnameParts.length > 2) {

            subdomains =
                hostnameParts.length - 2;
        }

        return {

            hostname: hostname,

            url_length:
                url.length,

            path_length:
                parsed.pathname.length,

            query_length:
                parsed.search.length,

            subdomain_count:
                subdomains
        };

    } catch (error) {

        return {

            hostname: "",

            url_length:
                url.length,

            path_length: 0,

            query_length: 0,

            subdomain_count: 0
        };
    }
}


// ===============================
// DOMAIN INTELLIGENCE
// ===============================

function updateDomainIntelligence(
    data,
    scannedURL
) {

    if (!domainIntelligence) return;

    const liveData =
        data.domain_intelligence || {};

    const urlInfo =
        getURLInformation(scannedURL);

    console.log(
        "Domain Intelligence received:",
        liveData
    );


    // ==========================================
    // HOSTNAME
    // ==========================================

    const hostname =
        liveData.hostname ||
        urlInfo.hostname ||
        "--";

    setValue(
        infoHostname,
        hostname
    );


    // ==========================================
    // BASIC URL INFORMATION
    // ==========================================

    setValue(
        infoURLLength,
        liveData.url_length ??
        urlInfo.url_length
    );

    setValue(
        infoPathLength,
        liveData.path_length ??
        urlInfo.path_length
    );

    setValue(
        infoQueryLength,
        liveData.query_length ??
        urlInfo.query_length
    );

    setValue(
        infoSubdomains,
        liveData.subdomain_count ??
        urlInfo.subdomain_count
    );


    // ==========================================
    // DNS
    // ==========================================

    setBooleanValue(
        infoDNS,
        liveData.dns_resolves
    );

    setBooleanValue(
        infoMX,
        liveData.has_mx_record
    );

    setBooleanValue(
        infoTXT,
        liveData.has_txt_record
    );

    setBooleanValue(
        infoNS,
        liveData.has_ns_record
    );

    setValue(
        infoIPCount,
        liveData.ip_count
    );

    setValue(
        infoCNAME,
        liveData.cname_count
    );


    // ==========================================
    // WHOIS
    // ==========================================

    // Domain Age
    if (
        liveData.domain_age_days !== null &&
        liveData.domain_age_days !== undefined &&
        liveData.domain_age_days !== ""
    ) {

        const age =
            Number(
                liveData.domain_age_days
            );

        if (Number.isFinite(age)) {

            setValue(
                infoDomainAge,
                age.toLocaleString(),
                " days"
            );

        } else {

            setValue(
                infoDomainAge,
                "Unavailable"
            );
        }

    } else {

        setValue(
            infoDomainAge,
            "Unavailable"
        );
    }


    // Recent Domain
    setBooleanValue(
        infoRecentDomain,
        liveData.domain_is_recent
    );


    // Registrar
    setBooleanValue(
        infoRegistrar,
        liveData.registrar_valid
    );


    // Name Servers
    if (
        liveData.name_servers_count !== null &&
        liveData.name_servers_count !== undefined &&
        liveData.name_servers_count !== ""
    ) {

        const count =
            Number(
                liveData.name_servers_count
            );

        if (Number.isFinite(count)) {

            setValue(
                infoNameServers,
                count
            );

        } else {

            setValue(
                infoNameServers,
                "Unavailable"
            );
        }

    } else {

        setValue(
            infoNameServers,
            "Unavailable"
        );
    }


    // Privacy Protected
    setBooleanValue(
        infoPrivacy,
        liveData.is_privacy_protected
    );
}


// ===============================
// HISTORY
// ===============================

function getHistory() {

    try {

        return JSON.parse(
            localStorage.getItem(
                "phishguard_history"
            ) || "[]"
        );

    } catch (error) {

        return [];
    }
}


function saveToHistory(
    url,
    result,
    phishingProbability
) {

    let history =
        getHistory();

    const item = {

        url: url,

        result: result,

        phishing_probability:
            phishingProbability,

        time:
            new Date().toLocaleString()
    };

    history.unshift(item);

    history =
        history.slice(0, 10);

    localStorage.setItem(
        "phishguard_history",
        JSON.stringify(history)
    );

    renderHistory();
}


function renderHistory() {

    if (!historyList) return;

    const history =
        getHistory();

    if (history.length === 0) {

        historyList.innerHTML =
            '<p class="empty-history">No scans yet.</p>';

        return;
    }

    historyList.innerHTML = "";

    history.forEach((item) => {

        const historyItem =
            document.createElement("div");

        historyItem.className =
            "history-item";

        const isPhishing =
            item.result &&
            item.result
                .toLowerCase()
                .includes("phishing");

        historyItem.innerHTML = `

            <div class="history-main">

                <span class="history-status ${isPhishing ? "phishing" : "legitimate"}">
                    ${isPhishing ? "⚠" : "✓"}
                </span>

                <div class="history-url">

                    <strong>
                        ${escapeHTML(item.url)}
                    </strong>

                    <small>
                        ${escapeHTML(
                            item.time || "Unknown time"
                        )}
                    </small>

                </div>

            </div>

            <div class="history-probability">

                ${Number(
                    item.phishing_probability || 0
                ).toFixed(2)}%

            </div>
        `;

        historyList.appendChild(
            historyItem
        );
    });
}


// ===============================
// HTML ESCAPE
// ===============================

function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


// ===============================
// SCAN URL
// ===============================

async function scanURL() {

    const url =
        urlInput.value.trim();

    if (!url) {

        alert(
            "Please enter a URL."
        );

        return;
    }

    scanButton.disabled = true;

    scanButton.textContent =
        "Scanning...";

    resetDomainIntelligence();

    resetSecurityAnalysis();

    try {

        console.log(
            "Sending URL to:",
            API_URL
        );

        console.log(
            "URL:",
            url
        );

        const response =
            await fetch(
                `${API_URL}/scan`,
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            url: url
                        })
                }
            );

        if (!response.ok) {

            throw new Error(
                `Server returned ${response.status}`
            );
        }

        const data =
            await response.json();

        console.log(
            "===================================="
        );

        console.log(
            "PHISHGUARD SCAN RESPONSE"
        );

        console.log(
            "===================================="
        );

        console.log(
            data
        );

        console.log(
            "Security Analysis:",
            data.security_analysis
        );

        console.log(
            "Domain Intelligence:",
            data.domain_intelligence
        );

        console.log(
            "===================================="
        );


        if (!data.success) {

            throw new Error(
                data.error ||
                "Unable to analyze this URL."
            );
        }


        // ======================================
        // RESULT
        // ======================================

        const prediction =
            Number(
                data.prediction
            );

        const legitProbabilityValue =
            Number(
                data.legitimate_probability ?? 0
            ).toFixed(2);

        const phishingProbabilityValue =
            Number(
                data.phishing_probability ?? 0
            ).toFixed(2);


        if (resultURL) {

            resultURL.textContent =
                data.url || url;
        }

        if (legitimateProbability) {

            legitimateProbability.textContent =
                `${legitProbabilityValue}%`;
        }

        if (phishingProbability) {

            phishingProbability.textContent =
                `${phishingProbabilityValue}%`;
        }


        // ======================================
        // LEGITIMATE
        // ======================================

        if (prediction === 0) {

            if (resultTitle) {

                resultTitle.textContent =
                    "Likely Legitimate";
            }

            if (resultIcon) {

                resultIcon.textContent =
                    "✓";
            }

            if (resultMessage) {

                resultMessage.textContent =
                    "The URL appears to be legitimate based on the analyzed features.";
            }

            if (resultCard) {

                resultCard.classList.remove(
                    "phishing",
                    "error"
                );

                resultCard.classList.add(
                    "legitimate"
                );
            }

        }


        // ======================================
        // PHISHING
        // ======================================

        else {

            if (resultTitle) {

                resultTitle.textContent =
                    "Potential Phishing";
            }

            if (resultIcon) {

                resultIcon.textContent =
                    "⚠";
            }

            if (resultMessage) {

                resultMessage.textContent =
                    "The URL shows characteristics commonly associated with phishing websites.";
            }

            if (resultCard) {

                resultCard.classList.remove(
                    "legitimate",
                    "error"
                );

                resultCard.classList.add(
                    "phishing"
                );
            }
        }


        // ======================================
        // SECURITY ANALYSIS
        // ======================================

        updateSecurityAnalysis(
            data
        );


        // ======================================
        // DOMAIN INTELLIGENCE
        // ======================================

        updateDomainIntelligence(
            data,
            data.url || url
        );


        // ======================================
        // HISTORY
        // ======================================

        saveToHistory(
            data.url || url,
            data.result ||
                "Unknown",
            data.phishing_probability ||
                0
        );


        // ======================================
        // SHOW RESULT
        // ======================================

        showResultSections();

        scrollToResult();

    }

    catch (error) {

        console.error(
            "PhishGuard scan error:",
            error
        );

        if (resultTitle) {

            resultTitle.textContent =
                "Scan Failed";
        }

        if (resultIcon) {

            resultIcon.textContent =
                "!";
        }

        if (resultURL) {

            resultURL.textContent =
                url;
        }

        if (resultMessage) {

            resultMessage.textContent =
                error.message ||
                "Unable to connect to the PhishGuard backend.";
        }

        if (resultCard) {

            resultCard.classList.remove(
                "legitimate",
                "phishing"
            );

            resultCard.classList.add(
                "error"
            );
        }

        showResultSections();
    }

    finally {

        scanButton.disabled =
            false;

        scanButton.textContent =
            "Scan URL";
    }
}


// ===============================
// ENTER KEY
// ===============================

if (urlInput) {

    urlInput.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key ===
                "Enter"
            ) {

                event.preventDefault();

                scanURL();
            }
        }
    );
}


// ===============================
// SCAN BUTTON
// ===============================

if (scanButton) {

    scanButton.addEventListener(
        "click",
        scanURL
    );
}


// ===============================
// CLEAR HISTORY
// ===============================

if (clearHistoryButton) {

    clearHistoryButton.addEventListener(
        "click",
        function () {

            localStorage.removeItem(
                "phishguard_history"
            );

            renderHistory();
        }
    );
}


// ===============================
// INITIALIZATION
// ===============================

resetDomainIntelligence();

resetSecurityAnalysis();

renderHistory();