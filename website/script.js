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

// Scanner element
const scannerEl = document.querySelector(".scanner");


// ===============================
// ANIMATED NUMBER COUNTER
// ===============================

function animateCounter(element, targetValue, duration = 800) {

    if (!element) return;

    const target = parseFloat(targetValue);

    if (isNaN(target)) {
        element.textContent = targetValue;
        return;
    }

    const startTime = performance.now();
    const startValue = 0;

    function update(currentTime) {

        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);

        const currentValue = startValue + (target - startValue) * eased;

        element.textContent = currentValue.toFixed(2) + "%";

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    element.textContent = "0.00%";
    requestAnimationFrame(update);
}


// ===============================
// STAGGERED ANIMATION HELPER
// ===============================

function animateStaggered(elements, className, baseDelay = 0, staggerMs = 80) {

    elements.forEach((el, index) => {

        el.classList.remove(className);
        el.offsetHeight; // force reflow

        setTimeout(() => {

            el.classList.add(className);

        }, baseDelay + (index * staggerMs));
    });
}


// ===============================
// SCANNING STATE ANIMATIONS
// ===============================

function startScanAnimation() {

    // Pulse the scanner bar
    if (scannerEl) {
        scannerEl.classList.add("scanning");
        scannerEl.style.position = "relative";
        scannerEl.style.overflow = "hidden";
    }

    // Disable and animate button
    scanButton.disabled = true;
    scanButton.innerHTML = 'Analyzing<span class="scan-dots"></span>';
}


function stopScanAnimation() {

    if (scannerEl) {
        scannerEl.classList.remove("scanning");
    }

    scanButton.disabled = false;
    scanButton.textContent = "Scan URL";
}


// ===============================
// SHOW RESULT WITH ANIMATIONS
// ===============================

function showResultAnimated() {

    if (resultCard) {

        // Remove old animation classes
        resultCard.classList.remove("animate-in");

        // Show the card
        resultCard.style.setProperty(
            "display",
            "block",
            "important"
        );

        // Trigger animation
        resultCard.offsetHeight; // force reflow
        resultCard.classList.add("animate-in");

        // Animate the icon with pop effect
        if (resultIcon) {
            resultIcon.classList.remove("animate-pop");
            resultIcon.offsetHeight;

            setTimeout(() => {
                resultIcon.classList.add("animate-pop");
            }, 200);
        }

        // Animate probability boxes with counter
        const probBoxes = resultCard.querySelectorAll(".probability-box");

        probBoxes.forEach((box, i) => {

            box.classList.remove("counting");
            box.offsetHeight;

            setTimeout(() => {
                box.classList.add("counting");
            }, 400 + i * 150);
        });

        // Stagger the analysis items
        const analysisItemsLocal = resultCard.querySelectorAll(".analysis-item");

        analysisItemsLocal.forEach(item => {
            item.classList.remove("animate-slide");
        });

        animateStaggered(
            Array.from(analysisItemsLocal),
            "animate-slide",
            600,
            60
        );
    }

    // Show and animate domain intelligence
    if (domainIntelligence) {

        domainIntelligence.classList.remove("animate-in");

        domainIntelligence.style.setProperty(
            "display",
            "block",
            "important"
        );

        domainIntelligence.offsetHeight;

        setTimeout(() => {

            domainIntelligence.classList.add("animate-in");

            // Stagger intelligence items
            const intelItems = domainIntelligence.querySelectorAll(
                ".intelligence-item"
            );

            intelItems.forEach(item => {
                item.classList.remove("animate-fade");
            });

            animateStaggered(
                Array.from(intelItems),
                "animate-fade",
                300,
                50
            );

        }, 400);
    }

    // Show and animate history
    if (historySection) {

        historySection.classList.remove("animate-in");

        historySection.style.setProperty(
            "display",
            "block",
            "important"
        );

        historySection.offsetHeight;

        setTimeout(() => {
            historySection.classList.add("animate-in");
        }, 700);
    }
}


// ===============================
// SMOOTH SCROLL TO RESULT
// ===============================

function scrollToResult() {

    if (!resultCard) return;

    setTimeout(() => {

        const rect = resultCard.getBoundingClientRect();
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const targetY = scrollTop + rect.top - 100;

        window.scrollTo({
            top: targetY,
            behavior: "smooth"
        });

    }, 250);
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
            "analysis-danger",
            "animate-slide"
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

    setValue(infoHostname, null);
    setValue(infoURLLength, null);
    setValue(infoPathLength, null);
    setValue(infoQueryLength, null);
    setValue(infoSubdomains, null);

    setBooleanValue(infoDNS, null);
    setBooleanValue(infoMX, null);
    setBooleanValue(infoTXT, null);
    setBooleanValue(infoNS, null);
    setValue(infoIPCount, null);
    setValue(infoCNAME, null);

    setValue(infoDomainAge, null);
    setBooleanValue(infoRecentDomain, null);
    setBooleanValue(infoRegistrar, null);
    setValue(infoNameServers, null);
    setBooleanValue(infoPrivacy, null);
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
    phishingProbabilityValue
) {

    let history =
        getHistory();

    const item = {

        url: url,

        result: result,

        phishing_probability:
            phishingProbabilityValue,

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

    renderHistory(true);
}


function renderHistory(animateFirst = false) {

    if (!historyList) return;

    const history =
        getHistory();

    if (history.length === 0) {

        historyList.innerHTML =
            '<p class="empty-history">No scans yet.</p>';

        return;
    }

    historyList.innerHTML = "";

    history.forEach((item, index) => {

        const historyItem =
            document.createElement("div");

        historyItem.className =
            "history-item";

        // Animate the first (newest) item
        if (animateFirst && index === 0) {
            historyItem.classList.add("animate-new");
        }

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

        // Shake the scanner input
        if (scannerEl) {
            scannerEl.style.animation = "none";
            scannerEl.offsetHeight;
            scannerEl.style.animation = "shake 0.4s ease";
        }

        return;
    }

    // Start scanning animation
    startScanAnimation();

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
        // STOP SCAN ANIMATION
        // ======================================

        stopScanAnimation();


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

        // Animate counters instead of setting directly
        if (legitimateProbability) {

            animateCounter(
                legitimateProbability,
                legitProbabilityValue,
                900
            );
        }

        if (phishingProbability) {

            animateCounter(
                phishingProbability,
                phishingProbabilityValue,
                900
            );
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
        // ANIMATED SHOW + SCROLL
        // ======================================

        showResultAnimated();

        scrollToResult();

    }

    catch (error) {

        stopScanAnimation();

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

        showResultAnimated();
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