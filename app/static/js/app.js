document.addEventListener("DOMContentLoaded", () => {
    // --- Fetch backend status ---
    fetch("/api/status")
        .then((r) => r.json())
        .then((data) => {
            const el = document.getElementById("backend-info");
            if (el) {
                const pcap = data.pcap_backend === "scapy" ? "scapy" : "stdlib";
                const ssh = data.ssh_backend === "paramiko" ? "paramiko" : "subprocess+ssh";
                el.textContent = `Backends: pcap=${pcap}, ssh=${ssh}`;
                el.classList.remove("hidden");
            }
        })
        .catch(() => {});

    // --- Tab Navigation (with ARIA) ---
    const tabs = document.querySelectorAll(".tab");
    const tabContents = document.querySelectorAll(".tab-content");

    tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            tabs.forEach((t) => {
                t.classList.remove("active");
                t.setAttribute("aria-selected", "false");
            });
            tabContents.forEach((tc) => tc.classList.remove("active"));
            tab.classList.add("active");
            tab.setAttribute("aria-selected", "true");
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
    let activeAbortController = null;

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

    /**
     * Create an AbortController for fetch requests.
     * Aborts any previously active request to prevent race conditions.
     */
    function createAbortController() {
        if (activeAbortController) {
            activeAbortController.abort();
        }
        activeAbortController = new AbortController();
        return activeAbortController;
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

        const controller = createAbortController();
        showLoading();
        try {
            const resp = await fetch("/api/upload", {
                method: "POST",
                body: formData,
                signal: controller.signal,
            });
            const data = await resp.json();
            hideLoading();
            if (!resp.ok) {
                showError(data.error || "Upload failed");
                return;
            }
            displayParsedResults(data);
        } catch (err) {
            hideLoading();
            if (err.name !== "AbortError") {
                showError(`Request failed: ${err.message}`);
            }
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

        const controller = createAbortController();
        showLoading();
        try {
            const resp = await fetch("/api/ssh/read", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
                signal: controller.signal,
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
            if (err.name !== "AbortError") {
                showError(`Request failed: ${err.message}`);
            }
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

        const controller = createAbortController();
        showLoading();
        try {
            const resp = await fetch("/api/ssh/tshark", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
                signal: controller.signal,
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
            if (err.name !== "AbortError") {
                showError(`Request failed: ${err.message}`);
            }
        }
    });

    // --- Display parsed pcap results ---
    function displayParsedResults(data) {
        allPackets = data.packets ?? [];
        const summary = data.summary ?? {};

        // Summary
        document.getElementById("total-packets").textContent = summary.total_packets ?? 0;
        document.getElementById("unique-sources").textContent = summary.unique_sources ?? 0;
        document.getElementById("unique-destinations").textContent = summary.unique_destinations ?? 0;

        // Protocol bars
        const protocolBars = document.getElementById("protocol-bars");
        protocolBars.innerHTML = "";
        const protocols = summary.protocols ?? {};
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
                const color = protocolColors[proto] ?? "var(--accent-other)";
                const bar = document.createElement("div");
                bar.className = "protocol-bar";
                bar.innerHTML = `
                    <span class="protocol-bar-label">${escapeHtml(proto)}</span>
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
        const fragment = document.createDocumentFragment();

        for (const pkt of packets) {
            const protoClass = `proto-${pkt.protocol.toLowerCase()}`;
            const tr = document.createElement("tr");
            tr.tabIndex = 0;
            tr.setAttribute("data-pkt-no", pkt.no);
            tr.setAttribute("title", "Click to view hex dump");
            tr.innerHTML = `
                <td>${pkt.no}</td>
                <td>${escapeHtml(pkt.src)}</td>
                <td>${escapeHtml(pkt.dst)}</td>
                <td class="${protoClass}"><strong>${escapeHtml(pkt.protocol)}</strong></td>
                <td>${pkt.length}</td>
                <td>${escapeHtml(pkt.info)}</td>
            `;
            tr.addEventListener("click", () => openHexDump(pkt.no, pkt));
            tr.addEventListener("keydown", (e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    openHexDump(pkt.no, pkt);
                }
            });
            fragment.appendChild(tr);
        }

        packetTbody.appendChild(fragment);
    }

    // --- Filter (debounced) ---
    let filterTimeout = null;
    packetFilter.addEventListener("input", () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(() => {
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
        }, 150);
    });

    // --- Display tshark results ---
    function displayTsharkResults(data) {
        tsharkMeta.textContent = `Command: ${data.command ?? "N/A"}`;
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

    // =========================================================
    // Byte Inspector — Wireshark-like 3-pane modal
    // =========================================================

    const hexModal    = document.getElementById("hexdump-modal");
    const hexTitle    = document.getElementById("hexdump-title");
    const hexLoading  = document.getElementById("hexdump-loading");
    const hexClose    = document.getElementById("hexdump-close");
    const biTree      = document.getElementById("bi-tree");
    const biHexdump   = document.getElementById("bi-hexdump");
    const biPayload   = document.getElementById("bi-payload");
    const biPayTitle  = document.getElementById("bi-payload-title");
    const biLegend    = document.getElementById("bi-legend");

    hexClose.addEventListener("click", () => hexModal.close());
    hexModal.addEventListener("click", (e) => {
        if (e.target === hexModal) hexModal.close();
    });

    // Per-section color palette
    const SEC_CLASSES = ["bi-sec-0","bi-sec-1","bi-sec-2","bi-sec-3",
                         "bi-sec-4","bi-sec-5","bi-sec-6","bi-sec-7"];
    const SEC_COLORS  = ["#ec4899","#3b82f6","#22d3ee","#22c55e",
                         "#f59e0b","#8b5cf6","#ef4444","#64748b"];

    function secClass(idx) { return SEC_CLASSES[idx % SEC_CLASSES.length]; }
    function secColor(idx) { return SEC_COLORS[idx % SEC_COLORS.length]; }

    async function openHexDump(packetNo, pkt) {
        hexModal.showModal();
        hexTitle.textContent =
            `Packet #${packetNo} \u2014 ${pkt.protocol} \u2014 ${pkt.src} \u2192 ${pkt.dst} (${pkt.length} bytes)`;

        // Reset panes
        biTree.innerHTML = "";
        biHexdump.innerHTML = "";
        biPayload.innerHTML = "";
        biPayload.classList.add("hidden");
        biPayTitle.classList.add("hidden");
        biLegend.innerHTML = "";
        hexLoading.classList.remove("hidden");
        document.getElementById("hexdump-body").classList.add("hidden");

        try {
            const resp = await fetch(`/api/hexdump/${packetNo}`);
            const data = await resp.json();
            hexLoading.classList.add("hidden");
            document.getElementById("hexdump-body").classList.remove("hidden");

            if (!resp.ok) {
                biTree.innerHTML =
                    `<p style="color:var(--error);padding:1rem">${escapeHtml(data.error || "Failed to load")}</p>`;
                return;
            }

            const sections = data.sections ?? [];
            const rawBytes = data.bytes ?? [];

            if (!sections.length) {
                biTree.innerHTML =
                    `<p style="color:var(--text-muted);padding:1rem">No data available.</p>`;
                return;
            }

            // Build lookup: "sIdx:fIdx" -> Set<absOffset>
            const fieldToBytes = new Map();
            sections.forEach((sec, sIdx) => {
                (sec.fields ?? []).forEach((f, fIdx) => {
                    const key = `${sIdx}:${fIdx}`;
                    const set = new Set();
                    for (let b = 0; b < f.length; b++) set.add(f.offset + b);
                    fieldToBytes.set(key, set);
                });
            });

            // Build per-byte → section index array
            const byteToSection = new Uint8Array(rawBytes.length).fill(255);
            sections.forEach((sec, sIdx) => {
                const end = Math.min(sec.offset + sec.length, rawBytes.length);
                for (let i = sec.offset; i < end; i++) byteToSection[i] = sIdx;
            });

            // ---- Legend ----
            sections.forEach((sec, sIdx) => {
                const chip = document.createElement("span");
                chip.className = "bi-legend-chip";
                chip.style.background = secColor(sIdx);
                chip.textContent = sec.name.replace(/ Header$/, "").replace(/ \(.*\)$/, "");
                biLegend.appendChild(chip);
            });

            // ---- Interactive hex dump (right pane) ----
            const hexFrag = document.createDocumentFragment();
            const byteSpans = [];   // indexed by absOffset

            for (let rowStart = 0; rowStart < rawBytes.length; rowStart += 16) {
                const row = document.createElement("div");
                row.className = "bi-hex-row";

                const offsetSpan = document.createElement("span");
                offsetSpan.className = "bi-hex-row-offset";
                offsetSpan.textContent = rowStart.toString(16).toUpperCase().padStart(4, "0");
                row.appendChild(offsetSpan);

                const bytesDiv = document.createElement("div");
                bytesDiv.className = "bi-hex-bytes";

                let ascii = "";
                for (let g = 0; g < 2; g++) {
                    const grp = document.createElement("span");
                    grp.className = "bi-hex-group";
                    for (let b = 0; b < 8; b++) {
                        const absOff = rowStart + g * 8 + b;
                        if (absOff >= rawBytes.length) break;
                        const byteVal = rawBytes[absOff];
                        const sIdx = byteToSection[absOff];
                        const sp = document.createElement("span");
                        sp.className = "hb" + (sIdx < 255 ? " " + secClass(sIdx) : "");
                        sp.dataset.abs = absOff;
                        sp.textContent = byteVal.toString(16).toUpperCase().padStart(2, "0");
                        grp.appendChild(sp);
                        byteSpans[absOff] = sp;
                        ascii += (byteVal >= 0x20 && byteVal < 0x7F)
                            ? String.fromCharCode(byteVal) : ".";
                    }
                    bytesDiv.appendChild(grp);
                }

                const asciiSpan = document.createElement("span");
                asciiSpan.className = "bi-hex-ascii";
                asciiSpan.textContent = `|${ascii}|`;

                row.appendChild(bytesDiv);
                row.appendChild(asciiSpan);
                hexFrag.appendChild(row);
            }
            biHexdump.appendChild(hexFrag);

            // ---- Protocol tree (left pane) ----
            const treeFrag = document.createDocumentFragment();
            sections.forEach((sec, sIdx) => {
                const secDiv = document.createElement("div");
                secDiv.className = "bi-tree-section";

                const hdr = document.createElement("div");
                hdr.className = "bi-tree-section-hdr";

                const expandSpan = document.createElement("span");
                expandSpan.className = "bi-tree-expand";
                expandSpan.textContent = "\u25BC";

                const dot = document.createElement("span");
                dot.className = "bi-section-dot";
                dot.style.background = secColor(sIdx);

                const nameSpan = document.createElement("span");
                nameSpan.className = "bi-tree-section-name";
                nameSpan.textContent = sec.name;

                const metaSpan = document.createElement("span");
                metaSpan.className = "bi-tree-section-meta";
                const absHex = sec.offset.toString(16).toUpperCase().padStart(4, "0");
                metaSpan.textContent = `0x${absHex}  ${sec.length}B`;

                hdr.appendChild(expandSpan);
                hdr.appendChild(dot);
                hdr.appendChild(nameSpan);
                hdr.appendChild(metaSpan);

                hdr.addEventListener("click", () => secDiv.classList.toggle("collapsed"));

                hdr.addEventListener("mouseenter", () => {
                    for (let i = sec.offset; i < sec.offset + sec.length && i < byteSpans.length; i++) {
                        if (byteSpans[i]) byteSpans[i].classList.add("highlighted");
                    }
                });
                hdr.addEventListener("mouseleave", () => {
                    for (let i = sec.offset; i < sec.offset + sec.length && i < byteSpans.length; i++) {
                        if (byteSpans[i]) byteSpans[i].classList.remove("highlighted");
                    }
                });

                secDiv.appendChild(hdr);

                // Fields list
                const fieldsDiv = document.createElement("div");
                fieldsDiv.className = "bi-tree-fields";

                if (sec.fields && sec.fields.length) {
                    sec.fields.forEach((field, fIdx) => {
                        const fDiv = document.createElement("div");
                        fDiv.className = "bi-tree-field";

                        const nameEl = document.createElement("span");
                        nameEl.className = "bi-tree-field-name";
                        nameEl.title = field.name;
                        nameEl.textContent = field.name;

                        const valEl = document.createElement("span");
                        valEl.className = "bi-tree-field-value";
                        valEl.textContent = field.value ?? "";

                        const offEl = document.createElement("span");
                        offEl.className = "bi-tree-field-offset";
                        const fieldAbsHex = field.offset.toString(16).toUpperCase().padStart(4, "0");
                        let offsetLabel = `abs 0x${fieldAbsHex}  \u00B7  ${field.length} byte${field.length !== 1 ? "s" : ""}`;
                        if (sec.payload_relative) {
                            const relOff = field.offset - sec.offset;
                            offsetLabel += `  \u00B7  payload[0x${relOff.toString(16).toUpperCase().padStart(4, "0")}]`;
                        }
                        offEl.textContent = offsetLabel;

                        fDiv.appendChild(nameEl);
                        fDiv.appendChild(valEl);
                        fDiv.appendChild(offEl);

                        const key = `${sIdx}:${fIdx}`;
                        fDiv.addEventListener("mouseenter", () => {
                            fDiv.classList.add("highlighted");
                            (fieldToBytes.get(key) ?? new Set()).forEach((abs) => {
                                if (byteSpans[abs]) byteSpans[abs].classList.add("highlighted");
                            });
                            if (byteSpans[field.offset]) {
                                byteSpans[field.offset].scrollIntoView(
                                    { block: "nearest", behavior: "smooth" }
                                );
                            }
                        });
                        fDiv.addEventListener("mouseleave", () => {
                            fDiv.classList.remove("highlighted");
                            (fieldToBytes.get(key) ?? new Set()).forEach((abs) => {
                                if (byteSpans[abs]) byteSpans[abs].classList.remove("highlighted");
                            });
                        });

                        fieldsDiv.appendChild(fDiv);
                    });
                } else if (sec.payload_relative) {
                    const note = document.createElement("div");
                    note.style.cssText = "font-size:0.74rem;color:var(--text-muted);padding:0.2rem 0.25rem";
                    note.textContent = `${sec.length} bytes \u2014 see Payload Byte Array below`;
                    fieldsDiv.appendChild(note);
                }

                secDiv.appendChild(fieldsDiv);
                treeFrag.appendChild(secDiv);
            });
            biTree.appendChild(treeFrag);

            // ---- Payload byte array view ----
            const payloadSection = sections.find((s) => s.payload_relative);
            if (payloadSection && payloadSection.length > 0) {
                biPayTitle.classList.remove("hidden");
                biPayload.classList.remove("hidden");

                const pre = document.createElement("pre");
                pre.className = "bi-payload-pre";

                const payBytes = rawBytes.slice(
                    payloadSection.offset,
                    payloadSection.offset + payloadSection.length,
                );
                let payHtml = "";
                for (let i = 0; i < payBytes.length; i += 16) {
                    const chunk = payBytes.slice(i, i + 16);
                    const offStr = i.toString(16).toUpperCase().padStart(4, "0");
                    const hexLeft  = chunk.slice(0, 8).map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ").padEnd(23, " ");
                    const hexRight = chunk.slice(8).map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ").padEnd(23, " ");
                    const ascii = Array.from(chunk).map((b) => (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : ".").join("");
                    payHtml +=
                        `<span class="pa-offset">payload[0x${offStr}]</span>  ` +
                        `<span class="pa-hex">${escapeHtml(hexLeft)}  ${escapeHtml(hexRight)}</span>  ` +
                        `<span class="pa-ascii">|${escapeHtml(ascii)}|</span>\n`;
                }
                pre.innerHTML = payHtml;
                biPayload.appendChild(pre);
            }

        } catch (err) {
            hexLoading.classList.add("hidden");
            document.getElementById("hexdump-body").classList.remove("hidden");
            biTree.innerHTML =
                `<p style="color:var(--error);padding:1rem">Request failed: ${escapeHtml(err.message)}</p>`;
        }
    }

    // --- Utility ---
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str ?? "";
        return div.innerHTML;
    }
});
