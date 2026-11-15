async function api(url, options = {}) {
    const res = await fetch(url, options);
    let data;

    try {
        data = await res.json();
    } catch (_) {
        throw new Error(
            `Server returned a non-JSON response (${res.status}). Check the Flask terminal.`
        );
    }

    if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
    }

    return data;
}

function pct(v) {
    return v == null ? "N/A" : (v * 100).toFixed(2) + "%";
}

function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[c]));
}

async function loadStatus() {
    try {
        const s = await api("/api/status");

        document.getElementById("topStatus").textContent =
            s.ready ? "Models connected" : "Models missing";

        const el = document.getElementById("modelNotice");

        if (el) {
            document.getElementById("noticeTitle").textContent =
                s.ready ? "Saved models connected" : "Model files not found";

            document.getElementById("noticeText").textContent = s.ready
                ? `${s.models.length} saved model(s) loaded. ${s.feature_count} input features available.`
                : "Copy your saved model, scaler, label encoder and feature list into the models folder, then restart Flask.";

            el.classList.toggle("notice-good", s.ready);
        }

        setText("statStatus", s.ready ? "Ready" : "Pending");
        setText("statFeatures", s.feature_count);
        setText("statModels", s.models.length);

        const list = document.getElementById("modelList");

        if (list) {
            const benchmarks = {
                "Random Forest": "99.8281%",
                "Decision Tree": "99.8264%",
                "XGBoost": "99.6549%",
            };
            list.innerHTML = Object.entries(benchmarks)
                .map(([name, accuracy]) => `
                    <div class="model-row">
                        <span class="model-symbol">◇</span>
                        <span>${name}</span>
                        <b class="${accuracy === "Not reported" ? "muted" : "green"}">${accuracy}</b>
                    </div>
                `)
                .join("");
        }

        if (document.getElementById("featureGrid")) {
            buildForm(s.features);
        }
    } catch (e) {
        setText("topStatus", "API unavailable");

        const n = document.getElementById("noticeText");

        if (n) {
            n.textContent =
                "Flask API is not responding. Start the server with py app.py.";
        }

        const grid = document.getElementById("featureGrid");

        if (grid && grid.children.length === 0) {
            grid.innerHTML = `
                <p class="error-box">
                    Could not load feature status from Flask.
                    Refresh the page after checking the server.
                </p>
            `;
        }
    }
}

function setText(id, t) {
    const el = document.getElementById(id);

    if (el) {
        el.textContent = t;
    }
}

function buildForm(features) {
    const root = document.getElementById("featureGrid");

    if (!root || root.dataset.built === "1") {
        return;
    }

    root.dataset.built = "1";

    root.innerHTML = features.map(f => `
        <label class="field">
            <span>${esc(f)}</span>
            <input
                type="number"
                step="any"
                name="${esc(f)}"
                data-feature="${esc(f)}"
                placeholder="Enter ${esc(f.toLowerCase())}"
                value="0"
            >
        </label>
    `).join("");
}

function formValues() {
    const obj = {};

    document.querySelectorAll("[data-feature]").forEach(i => {
        obj[i.dataset.feature] = Number(i.value || 0);
    });

    return obj;
}

function setInputs(values) {
    document.querySelectorAll("[data-feature]").forEach(i => {
        const v =
            values[i.dataset.feature] ??
            values[i.dataset.feature.trim()] ??
            0;

        i.value = v;
    });
}

function sample(preset, features) {
    const o = {};

    features.forEach(f => o[f] = 0);

    if (preset === "benign") {
        Object.assign(o, {
            "Destination Port": 80,
            "Flow Duration": 50000,
            "Total Fwd Packets": 4,
            "Total Backward Packets": 4,
            "Total Length of Fwd Packets": 300,
            "Total Length of Bwd Packets": 1200,
            "Fwd Packet Length Max": 150,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 75,
            "Bwd Packet Length Max": 600,
            "Bwd Packet Length Min": 40,
            "Bwd Packet Length Mean": 300,
            "Flow Bytes/s": 30000,
            "Flow Packets/s": 160,
            "SYN Flag Count": 1,
            "ACK Flag Count": 1,
            "Average Packet Size": 187.5,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 8192
        });
    } 
else {
    Object.assign(o, {
        "Destination Port": 80,
        "Flow Duration": 1878,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 6,
        "Total Length of Fwd Packets": 382,
        "Total Length of Bwd Packets": 11595,
        "Fwd Packet Length Max": 382,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 127.3333333,
        "Fwd Packet Length Std": 220.5478028,
        "Bwd Packet Length Max": 4355,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 1932.5,
        "Bwd Packet Length Std": 2182.468304,
        "Flow Bytes/s": 6377529.286,
        "Flow Packets/s": 4792.332268,
        "Flow IAT Mean": 234.75,
        "Flow IAT Std": 229.1298758,
        "Flow IAT Max": 577,
        "Flow IAT Min": 15,
        "Fwd IAT Total": 975,
        "Fwd IAT Mean": 487.5,
        "Fwd IAT Std": 265.1650429,
        "Fwd IAT Max": 675,
        "Fwd IAT Min": 300,
        "Bwd IAT Total": 1780,
        "Bwd IAT Mean": 356,
        "Bwd IAT Std": 399.7880689,
        "Bwd IAT Max": 950,
        "Bwd IAT Min": 15,
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": 104,
        "Bwd Header Length": 200,
        "Fwd Packets/s": 1597.444089,
        "Bwd Packets/s": 3194.888179,
        "Min Packet Length": 0,
        "Max Packet Length": 4355,
        "Packet Length Mean": 1197.7,
        "Packet Length Std": 1886.332364,
        "Packet Length Variance": 3558249.789,
        "FIN Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 1,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": 2,
        "Average Packet Size": 1330.777778,
        "Avg Fwd Segment Size": 127.3333333,
        "Avg Bwd Segment Size": 1932.5,
        "Fwd Header Length.1": 104,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": 3,
        "Subflow Fwd Bytes": 382,
        "Subflow Bwd Packets": 6,
        "Subflow Bwd Bytes": 11595,
        "Init_Win_bytes_forward": 29200,
        "Init_Win_bytes_backward": 235,
        "act_data_pkt_fwd": 1,
        "min_seg_size_forward": 32,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0
    });
}


    return o;
}

async function runPrediction() {
    const btn = document.getElementById("analyseBtn");
    const out = document.getElementById("predictionResult");

    btn.disabled = true;
    btn.textContent = "Analysing…";

    out.classList.remove("hidden");
    out.innerHTML = '<p class="muted">Sending flow to Flask…</p>';

    try {
        const d = await api("/api/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(formValues())
        });

        out.innerHTML = `
            <div class="result-head">
                <div>
                    <span class="eyebrow">PREDICTION RESULT</span>
                    <h2>${esc(d.prediction)}</h2>

                    <p class="${d.is_attack ? "danger" : "green"}">
                        ${d.is_attack
                            ? "Potential attack detected"
                            : "Predicted benign traffic"}
                    </p>

                    <p class="muted small">
                        Predicted traffic class / attack type:
                        <b>${esc(d.prediction)}</b>
                    </p>
                </div>

                <div class="confidence">
                    <strong>${pct(d.confidence)}</strong>
                    <small>CONFIDENCE</small>
                </div>
            </div>


            <section class="explanation-box">
                <h3>Why did the model predict this?</h3>

                <p class="muted">
                    ${esc(
                        d.explanation?.summary ||
                        "Explanation is unavailable for these saved model files."
                    )}
                </p>

                ${d.explanation?.top_features?.length ? `
                    <div class="chart-box">
                        <canvas id="explanationChart"></canvas>
                    </div>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Feature</th>
                                    <th>Input value (model scale)</th>
                                    <th>SHAP impact / importance</th>
                                </tr>
                            </thead>

                            <tbody>
                                ${d.explanation.top_features.map(f => `
                                    <tr>
                                        <td>${esc(f.feature)}</td>
                                        <td>${Number(f.value).toPrecision(5)}</td>
                                        <td>
                                            ${f.impact == null
                                                ? (Number(f.importance) * 100).toFixed(2) + "%"
                                                : (f.impact > 0 ? "+" : "") +
                                                  Number(f.impact).toPrecision(5)}
                                        </td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>

                    <div class="explanation-plain">
                        <h4>Explanation in plain English</h4>

                        <p>
                            ${esc(
                                d.explanation.summary ||
                                "The model explanation is unavailable for this prediction."
                            )}
                        </p>

                        <p>
                            How to read the graph: a longer bar means a larger
                            contribution or higher learned importance in the selected
                            model. For SHAP, positive and negative values indicate
                            the direction of contribution to the selected class.
                            For global feature importance, the graph shows overall
                            importance learned during training and does not establish
                            the direction of this individual prediction.
                        </p>
                    </div>
                ` : ""}

            </section>
        `;

        if (window.Chart) {
            const confidenceCanvas = document.getElementById("confidenceChart");
            if (confidenceCanvas) {
                const existingConfidenceChart = Chart.getChart(confidenceCanvas);
                if (existingConfidenceChart) existingConfidenceChart.destroy();
                new Chart(confidenceCanvas, {
                type: "bar",
                data: {
                    labels: d.models.map(m => m.model),
                    datasets: [{
                        label: "Confidence (%)",
                        data: d.models.map(m =>
                            m.confidence == null ? 0 : m.confidence * 100
                        ),
                        backgroundColor: "#d6bd45",
                        borderColor: "#b89d28",
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
                });
            }

            const explanationCanvas = document.getElementById("explanationChart");
            if (explanationCanvas && d.explanation?.top_features?.length) {
                const existingExplanationChart = Chart.getChart(explanationCanvas);
                if (existingExplanationChart) existingExplanationChart.destroy();
                new Chart(explanationCanvas, {
                    type: "bar",
                    data: {
                        labels: d.explanation.top_features.map(f => f.feature),
                        datasets: [{
                            label: d.explanation.method === "SHAP"
                                ? "Absolute SHAP value"
                                : "Feature importance (%)",
                            data: d.explanation.top_features.map(f =>
                                d.explanation.method === "SHAP"
                                    ? Math.abs(f.impact || 0)
                                    : f.importance * 100
                            ),
                            backgroundColor: "#d6bd45",
                            borderColor: "#b89d28",
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: "y",
                        responsive: true,
                        scales: {
                            x: {
                                beginAtZero: true
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
            }
        }
    } catch (e) {
        out.innerHTML = `
            <div class="error-box">
                <b>Analysis failed</b>
                <p>${esc(e.message)}</p>
                <small>
                    Check that your saved models, scaler and feature list
                    come from the same notebook run.
                </small>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = 'Analyse traffic <b>↗</b>';
    }
}

async function upload(fileId, msgId, resultsId) {
    const input = document.getElementById(fileId);
    const msg = document.getElementById(msgId);
    const results = document.getElementById(resultsId);
    const btn = document.getElementById("uploadBtn");

    if (!input.files.length) {
        msg.textContent = "Choose a CSV or Excel file first.";
        return;
    }

    const fd = new FormData();
    fd.append("file", input.files[0]);
    const allResults = [];
    if (btn) btn.disabled = true;
    msg.textContent = "Uploading file…";

    if (results) results.innerHTML = `
        <section class="panel">
            <h3>Analysis progress</h3>
            <p id="streamProgress" class="muted">Preparing network flows…</p>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Row</th><th>Prediction</th><th>Confidence</th><th>Result</th></tr></thead>
                    <tbody id="streamRows"></tbody>
                </table>
            </div>
            <div id="fileVerdict"></div>
        </section>
    `;

    const progress = document.getElementById("streamProgress");
    const tableBody = document.getElementById("streamRows");
    const verdict = document.getElementById("fileVerdict");

    function renderVerdict(data, finished) {
        if (!verdict) return;
        if (data.attack_count > 0) {
            const attacks = allResults.filter(r => r.is_attack);
            verdict.innerHTML = `
                <div class="error-box">
                    <h3>Potential attack detected</h3>
                    <p>Detected ${data.attack_count} potential attack flow(s) in ${data.completed ?? data.rows} processed row(s).</p>
                    <p><b>Predicted attack classes:</b> ${esc([...new Set(attacks.map(r => r.prediction).filter(Boolean))].join(", "))}</p>
                    ${attacks.slice(0, 5).map(r => `
                        <section class="explanation-box">
                            <h4>Row ${r.row}: ${esc(r.prediction || "Potential attack")}</h4>
                            <p>${esc(r.explanation?.summary || "A class-specific explanation is unavailable for this flow.")}</p>
                            ${r.explanation?.top_features?.length ? `
                                <div class="table-wrap"><table>
                                    <thead><tr><th>Feature</th><th>Value</th><th>Impact / importance</th></tr></thead>
                                    <tbody>${r.explanation.top_features.slice(0, 5).map(f => `
                                        <tr><td>${esc(f.feature)}</td><td>${Number(f.value).toPrecision(5)}</td>
                                        <td>${f.impact == null ? (Number(f.importance) * 100).toFixed(2) + "%" : (f.impact > 0 ? "+" : "") + Number(f.impact).toPrecision(5)}</td></tr>
                                    `).join("")}</tbody>
                                </table></div>
                            ` : ""}
                        </section>
                    `).join("")}
                </div>
            `;
        } else if (finished && data.failed_count === 0) {
            verdict.innerHTML = `
                <div class="success-box">
                    <h3>No attacks detected</h3>
                    <p>All ${data.rows} analyzed network flows were classified as benign by the model.</p>
                </div>
            `;
        } else if (finished && data.failed_count > 0) {
            verdict.innerHTML = `
                <div class="error-box">
                    <h3>Analysis incomplete</h3>
                    <p>${data.failed_count} row(s) could not be analyzed. Do not treat failed rows as benign.</p>
                </div>
            `;
        } else if (data.attack_count === 0) {
            verdict.innerHTML = `<p class="muted">No attack has been detected in the completed rows so far. Analysis is still running.</p>`;
        }
    }

    function appendRows(rows) {
        if (!tableBody) return;
        for (const r of rows) {
            allResults.push(r);
            const tr = document.createElement("tr");
            const status = r.error ? "Failed" : r.is_attack ? "Potential attack" : "Benign";
            tr.innerHTML = `
                <td>${r.row}</td>
                <td>${esc(r.prediction || r.error || "Error")}</td>
                <td>${pct(r.confidence)}</td>
                <td class="${r.error ? "danger" : r.is_attack ? "danger" : "green"}">${status}</td>
            `;
            tableBody.appendChild(tr);
        }
    }

    try {
        const response = await fetch("/api/upload/stream", { method: "POST", body: fd });
        if (!response.ok) {
            let message = `Upload failed (${response.status})`;
            try { const e = await response.json(); message = e.error || message; } catch (_) {}
            throw new Error(message);
        }
        if (!response.body) throw new Error("This browser does not support streamed responses.");
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let finalData = null;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            for (const line of lines) {
                if (!line.trim()) continue;
                const event = JSON.parse(line);
                if (event.type === "start") {
                    msg.textContent = `Uploaded ${event.filename}. Starting analysis of ${event.rows} rows…`;
                    if (progress) progress.textContent = `0 / ${event.rows} rows analyzed`;
                } else if (event.type === "batch") {
                    appendRows(event.results || []);
                    if (progress) progress.textContent = `${event.completed} / ${event.total} rows analyzed`;
                    msg.textContent = `Analyzing… ${event.completed} of ${event.total} rows completed`;
                    renderVerdict({
                        attack_count: event.attack_count, benign_count: event.benign_count,
                        failed_count: event.failed_count, completed: event.completed, rows: event.total
                    }, false);
                } else if (event.type === "complete") {
                    finalData = event;
                    renderVerdict(event, true);
                }
            }
        }
        if (buffer.trim()) {
            const event = JSON.parse(buffer);
            if (event.type === "complete") finalData = event;
        }
        if (!finalData) throw new Error("The server ended the stream before sending a completion summary.");

        msg.textContent = `Completed: ${finalData.rows} rows from ${finalData.filename}. ${finalData.attack_count} potential attack(s), ${finalData.benign_count} benign, ${finalData.failed_count} failed.`;
        if (results) {
            const download = document.createElement("button");
            download.className = "button secondary";
            download.textContent = "Download results CSV";
            download.id = "downloadCsv";
            results.appendChild(download);
            download.onclick = () => {
                const rows = [
                    ["row", "prediction", "confidence", "is_attack", "error"],
                    ...allResults.map(r => [r.row, r.prediction || "", r.confidence ?? "", r.is_attack ?? "", r.error || ""])
                ];
                const csv = rows.map(row => row.map(v => `"${String(v ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
                const a = document.createElement("a");
                const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
                a.href = url;
                a.download = "xnids_predictions.csv";
                a.click();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
            };
        }
        if (typeof loadHistory === "function") loadHistory();
    } catch (e) {
        msg.textContent = e.message;
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function loadModels() {
    const table = document.getElementById("modelTable");

    if (!table) {
        return;
    }

    try {
        const d = await api("/api/models");
        table.innerHTML = d.models.map(m => `
            <tr>
                <td>${esc(m.name)}</td>
                <td>${m.test_accuracy == null ? "Not reported in notebook" : (m.test_accuracy * 100).toFixed(4) + "%"}</td>
                <td>${esc(m.dataset || "CICIDS2017")}</td>
            </tr>
        `).join("");
    } catch (e) {
        table.innerHTML = `<tr><td colspan="3">${esc(e.message)}</td></tr>`;
    }
}

async function loadHistory() {
    const root = document.getElementById("historyTable");
    const recent = document.getElementById("recentHistory");

    if (!root && !recent) return;

    try {
        const h = await api("/api/history");
        const empty = `<p class="muted">No predictions yet. Run an analysis first.</p>`;

        if (root) {
            root.innerHTML = h.length ? `
                <table>
                    <thead><tr><th>Time</th><th>Source</th><th>Prediction</th><th>Confidence</th></tr></thead>
                    <tbody>${h.map(x => `
                        <tr>
                            <td>${esc(x.timestamp || "")}</td>
                            <td>${esc(x.source || "Manual")}</td>
                            <td>${esc(x.prediction || "")}</td>
                            <td>${pct(x.confidence)}</td>
                        </tr>
                    `).join("")}</tbody>
                </table>
            ` : empty;
        }

        if (recent) {
            recent.innerHTML = h.length ? h.slice(0, 4).map(x => `
                <div class="history-row">
                    <span class="history-bullet"></span>
                    <div><b>${esc(x.prediction || "Unknown")}</b><small>${esc(x.timestamp || "")}</small></div>
                    <strong>${pct(x.confidence)}</strong>
                </div>
            `).join("") : empty;
        }
    } catch (e) {
        if (root) root.textContent = e.message;
        if (recent) recent.textContent = e.message;
    }
}

function setTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    try { localStorage.setItem("xnids-theme", selected); } catch (_) {}
    const toggle = document.getElementById("themeToggle");
    const icon = document.getElementById("themeIcon");
    const label = document.getElementById("themeLabel");
    const targetLabel = selected === "dark" ? "Light theme" : "Dark theme";
    if (toggle) {
        toggle.setAttribute("aria-label", `Switch to ${selected === "dark" ? "light" : "dark"} theme`);
        toggle.setAttribute("title", `Switch to ${selected === "dark" ? "light" : "dark"} theme`);
        toggle.setAttribute("aria-pressed", String(selected === "light"));
    }
    if (icon) icon.textContent = selected === "dark" ? "☼" : "◐";
    if (label) label.textContent = targetLabel;
    window.dispatchEvent(new CustomEvent("xnids:themechange", { detail: { theme: selected } }));
}

document.addEventListener("DOMContentLoaded", () => {
    setTheme(document.documentElement.dataset.theme || "dark");
    const themeToggle = document.getElementById("themeToggle");
    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
            setTheme(current === "dark" ? "light" : "dark");
        });
    }
    loadStatus();
    loadModels();
    loadHistory();

    const apply = document.getElementById("applyPreset");

    if (apply) {
        apply.onclick = () => {
            const p = document.getElementById("presetSelect").value;

            if (!p) {
                alert("Choose a sample first.");
                return;
            }

            api("/api/status")
                .then(s => setInputs(sample(p, s.features)))
                .catch(e => alert(e.message));
        };
    }

    const clear = document.getElementById("clearBtn");

    if (clear) {
        clear.onclick = () => {
            document.querySelectorAll("[data-feature]").forEach(i => {
                i.value = "0";
            });

            document.getElementById("presetSelect").value = "";

            const r = document.getElementById("predictionResult");

            r.classList.add("hidden");
            r.innerHTML = "";
        };
    }

    const analyse = document.getElementById("analyseBtn");

    if (analyse) {
        analyse.onclick = runPrediction;
    }

    const u = document.getElementById("uploadBtn");

    if (u) {
        u.onclick = () => upload(
            "trafficFile",
            "uploadMessage",
            "uploadResults"
        );
    }

    const u2 = document.getElementById("uploadBtn2");

    if (u2) {
        u2.onclick = () => upload(
            "trafficFile2",
            "uploadMessage2",
            "uploadResults"
        );
    }

    const rh = document.getElementById("refreshHistory");

    if (rh) {
        rh.onclick = loadHistory;
    }
});