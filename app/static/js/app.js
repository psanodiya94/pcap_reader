document.addEventListener("DOMContentLoaded", () => {
    // --- Tab Navigation ---
    const tabs = document.querySelectorAll(".tab");
    const tabContents = document.querySelectorAll(".tab-content");

    tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            tabs.forEach((t) => t.classList.remove("active"));
            tabContents.forEach((tc) => tc.classList.remove("active"));
            tab.classList.add("active");
            document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
            hideResults();
            hideError();
        });
    });

    // --- Elements ---
    const loading = document.getElementById("loading");
    const errorDisplay = document.getElementById("error-display");
    const errorMessage = document.getElementById("error-message");
    const results = document.getElementById("results");
    const summaryPanel = document.getElementById("summary-panel");
    const filterBar = document.getElementById("filter-bar");
    const packetTableWrapper = document.getElementById("packet-table-wrapper");
    const packetTbody = document.getElementById("packet-tbody");
    const tsharkOutputWrapper = document.getElementById("tshark-output-wrapper");
    const tsharkOutput = document.getElementById("tshark-output");
    const tsharkMeta = document.getElementById("tshark-meta");
    const packetFilter = document.getElementById("packet-filter");

    let allPackets = [];

    // --- Error handling ---
    document.getElementById("close-error").addEventListener("click", hideError);

    function showError(msg) {
        errorMessage.textContent = msg;
        errorDisplay.classList.remove("hidden");
    }

    function hideError() {
        errorDisplay.classList.add("hidden");
    }

    function showLoading() {
        loading.classList.remove("hidden");
        hideError();
        hideResults();
    }

    function hideLoading() {
        loading.classList.add("hidden");
    }

    function hideResults() {
        results.classList.add("hidden");
        summaryPanel.classList.add("hidden");
        filterBar.classList.add("hidden");
        packetTableWrapper.classList.add("hidden");
        tsharkOutputWrapper.classList.add("hidden");
    }

    // --- File upload label ---
    const pcapFile = document.getElementById("pcap-file");
    if (pcapFile) {
        pcapFile.addEventListener("change", () => {
            const label = document.getElementById("file-label");
            if (label && pcapFile.files.length > 0) {
                label.textContent = pcapFile.files[0].name;
            }
        });
    }

    // --- Local Upload ---
    document.getElementById("upload-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById("pcap-file");
        if (!fileInput.files.length) {
            showError("Please select a pcap file.");
            return;
        }

        const formData = new FormData();
        formData.append("file", fileInput.files[0]);

        showLoading();
        try {
            const resp = await fetch("/api/upload", { method: "POST", body: formData });
            const data = await resp.json();
            hideLoading();
            if (!resp.ok) {
                showError(data.error || "Upload failed");
                return;
            }
            displayParsedResults(data);
        } catch (err) {
            hideLoading();
            showError(`Request failed: ${err.message}`);
        }
    });

    // --- SSH Read ---
    document.getElementById("ssh-read-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            hostname: document.getElementById("ssh-host").value,
            port: parseInt(document.getElementById("ssh-port").value) || 22,
            username: document.getElementById("ssh-user").value,
            password: document.getElementById("ssh-pass").value || null,
            key_path: document.getElementById("ssh-key").value || null,
            remote_path: document.getElementById("ssh-remote-path").value,
        };

        showLoading();
        try {
            const resp = await fetch("/api/ssh/read", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await resp.json();
            hideLoading();
            if (!resp.ok) {
                showError(data.error || "SSH read failed");
                return;
            }
            displayParsedResults(data);
        } catch (err) {
            hideLoading();
            showError(`Request failed: ${err.message}`);
        }
    });

    // --- SSH Tshark ---
    document.getElementById("ssh-tshark-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            hostname: document.getElementById("tshark-host").value,
            port: parseInt(document.getElementById("tshark-port").value) || 22,
            username: document.getElementById("tshark-user").value,
            password: document.getElementById("tshark-pass").value || null,
            key_path: document.getElementById("tshark-key").value || null,
            remote_path: document.getElementById("tshark-remote-path").value,
            display_filter: document.getElementById("tshark-filter").value || null,
            max_packets: parseInt(document.getElementById("tshark-max").value) || 1000,
        };

        showLoading();
        try {
            const resp = await fetch("/api/ssh/tshark", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await resp.json();
            hideLoading();
            if (!resp.ok) {
                showError(data.error || "Tshark execution failed");
                return;
            }
            displayTsharkResults(data);
        } catch (err) {
            hideLoading();
            showError(`Request failed: ${err.message}`);
        }
    });

    // --- Display parsed pcap results ---
    function displayParsedResults(data) {
        allPackets = data.packets || [];
        const summary = data.summary || {};

        // Summary
        document.getElementById("total-packets").textContent = summary.total_packets || 0;
        document.getElementById("unique-sources").textContent = summary.unique_sources || 0;
        document.getElementById("unique-destinations").textContent = summary.unique_destinations || 0;

        // Protocol bars
        const protocolBars = document.getElementById("protocol-bars");
        protocolBars.innerHTML = "";
        const protocols = summary.protocols || {};
        const maxCount = Math.max(...Object.values(protocols), 1);

        const protocolColors = {
            TCP: "var(--accent-tcp)",
            UDP: "var(--accent-udp)",
            DNS: "var(--accent-dns)",
            HTTP: "var(--accent-http)",
            ICMP: "var(--accent-icmp)",
            ARP: "var(--accent-arp)",
        };

        Object.entries(protocols)
            .sort((a, b) => b[1] - a[1])
            .forEach(([proto, count]) => {
                const pct = (count / maxCount) * 100;
                const color = protocolColors[proto] || "var(--accent-other)";
                const bar = document.createElement("div");
                bar.className = "protocol-bar";
                bar.innerHTML = `
                    <span class="protocol-bar-label">${proto}</span>
                    <div class="protocol-bar-track">
                        <div class="protocol-bar-fill" style="width:${pct}%;background:${color}"></div>
                    </div>
                    <span class="protocol-bar-count">${count}</span>
                `;
                protocolBars.appendChild(bar);
            });

        renderPacketTable(allPackets);

        results.classList.remove("hidden");
        summaryPanel.classList.remove("hidden");
        filterBar.classList.remove("hidden");
        packetTableWrapper.classList.remove("hidden");
        tsharkOutputWrapper.classList.add("hidden");
    }

    function renderPacketTable(packets) {
        packetTbody.innerHTML = "";
        packets.forEach((pkt) => {
            const protoClass = `proto-${pkt.protocol.toLowerCase()}`;
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${pkt.no}</td>
                <td>${escapeHtml(pkt.src)}</td>
                <td>${escapeHtml(pkt.dst)}</td>
                <td class="${protoClass}"><strong>${escapeHtml(pkt.protocol)}</strong></td>
                <td>${pkt.length}</td>
                <td>${escapeHtml(pkt.info)}</td>
            `;
            packetTbody.appendChild(tr);
        });
    }

    // --- Filter ---
    packetFilter.addEventListener("input", () => {
        const query = packetFilter.value.toLowerCase();
        if (!query) {
            renderPacketTable(allPackets);
            return;
        }
        const filtered = allPackets.filter(
            (pkt) =>
                pkt.protocol.toLowerCase().includes(query) ||
                pkt.src.toLowerCase().includes(query) ||
                pkt.dst.toLowerCase().includes(query) ||
                pkt.info.toLowerCase().includes(query)
        );
        renderPacketTable(filtered);
    });

    // --- Display tshark results ---
    function displayTsharkResults(data) {
        tsharkMeta.textContent = `Command: ${data.command || "N/A"}`;
        tsharkOutput.textContent = data.output || "(no output)";

        if (data.errors) {
            tsharkOutput.textContent += `\n\n--- stderr ---\n${data.errors}`;
        }

        results.classList.remove("hidden");
        summaryPanel.classList.add("hidden");
        filterBar.classList.add("hidden");
        packetTableWrapper.classList.add("hidden");
        tsharkOutputWrapper.classList.remove("hidden");
    }

    // --- Utility ---
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str || "";
        return div.innerHTML;
    }
});
