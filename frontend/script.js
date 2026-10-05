const fileInput = document.getElementById("logFile");
const analyzeBtn = document.getElementById("analyzeBtn");
const statusText = document.getElementById("status");

const results = document.getElementById("results");

analyzeBtn.addEventListener("click", analyzeLog);


async function analyzeLog() {

    const file = fileInput.files[0];

    if (!file) {
        statusText.textContent = "Please select a log file.";
        return;
    }

    const formData = new FormData();

    formData.append("file", file);

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";
    statusText.textContent = "Analyzing security log...";

    try {

        const response = await fetch("/analyze-log", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Analysis failed.");
        }

        displayResults(data);

        statusText.textContent = "Analysis completed successfully.";

    } catch (error) {

        statusText.textContent = error.message;

    } finally {

        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze Log";
    }
}


function displayResults(data) {

    results.classList.remove("hidden");

    document.getElementById("filename").textContent =
        data.filename;

    document.getElementById("totalEvents").textContent =
        data.total_events;

    document.getElementById("totalThreats").textContent =
        data.threats_detected;

    document.getElementById("overallSeverity").textContent =
        data.severity;


    let high = 0;
    let medium = 0;
    let low = 0;

    data.threats.forEach(threat => {

        if (threat.severity === "High") {
            high++;
        }

        else if (threat.severity === "Medium") {
            medium++;
        }

        else {
            low++;
        }

    });


    document.getElementById("highCount").textContent = high;
    document.getElementById("mediumCount").textContent = medium;
    document.getElementById("lowCount").textContent = low;


    displayThreats(data.threats);

    displayIOCs(data.iocs);

    displayAI(data.ai_analysis);
}


function displayThreats(threats) {

    const container =
        document.getElementById("threatsContainer");

    container.innerHTML = "";

    if (threats.length === 0) {

        container.innerHTML =
            "<p>No threats detected.</p>";

        return;
    }


    threats.forEach(threat => {

        const card = document.createElement("div");

        card.className = "threat-card";

        card.innerHTML = `
            <h3>${escapeHtml(threat.type)}</h3>

            <p>
                <strong>IP:</strong>
                ${escapeHtml(threat.ip || "N/A")}
            </p>

            <p>
                <strong>Attempts:</strong>
                ${escapeHtml(String(threat.attempts))}
            </p>

            <p>
                <strong>Severity:</strong>
                ${escapeHtml(threat.severity)}
            </p>

            <p>
                <strong>Description:</strong>
                ${escapeHtml(threat.description)}
            </p>
        `;

        container.appendChild(card);
    });
}


function displayIOCs(iocs) {

    const container =
        document.getElementById("iocContainer");

    container.innerHTML = "";

    Object.entries(iocs).forEach(([type, values]) => {

        if (!values || values.length === 0) {
            return;
        }

        const group = document.createElement("div");

        group.className = "ioc-group";

        const title = document.createElement("h3");

        title.textContent =
            formatIOCName(type);

        group.appendChild(title);


        values.forEach(value => {

            const item =
                document.createElement("span");

            item.className = "ioc-item";

            item.textContent = value;

            group.appendChild(item);
        });


        container.appendChild(group);
    });


    if (!container.innerHTML) {

        container.innerHTML =
            "<p>No indicators of compromise found.</p>";
    }
}


function displayAI(ai) {

    document.getElementById("aiSummary").textContent =
        ai.summary || "No AI analysis available.";

    document.getElementById("recommendation").textContent =
        ai.recommendation || "No recommendation available.";
}


function formatIOCName(name) {

    return name
        .replaceAll("_", " ")
        .replace(/\b\w/g, char => char.toUpperCase());
}


function escapeHtml(value) {

    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}