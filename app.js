(function () {
  "use strict";

  var currentIoc = "";
  var currentType = "";
  var triageSampleId = "";
  var triageSubmittedTarget = "";
  var triageScreenshotObjectUrl = null;

  function byId(id) { return document.getElementById(id); }
  function sleep(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  function updateStatus(message) { byId("status-msg").textContent = message; }

  function defang(value) {
    if (!value) return "N/A";
    return String(value).replace(/^http/gi, "hxxp").replace(/\./g, "[.]");
  }

  function normalizeWorkerUrl(value) {
    return String(value || "").trim().replace(/\/+$/, "");
  }

  function getWorkerUrl() {
    return normalizeWorkerUrl(localStorage.getItem("socIntelWorkerUrl") || "");
  }

  function requireWorkerUrl() {
    var url = getWorkerUrl();
    if (!url) {
      throw new Error("Set your Cloudflare Worker URL first.");
    }
    return url;
  }

  async function apiFetch(path, options) {
    var response;
    var text;
    var payload;
    var base = requireWorkerUrl();
    response = await fetch(base + path, options || {});
    text = await response.text();
    try { payload = text ? JSON.parse(text) : null; } catch (error) { payload = text; }
    if (!response.ok) {
      throw new Error(payload && payload.error ? payload.error : (typeof payload === "string" && payload ? payload : ("HTTP " + response.status)));
    }
    return payload;
  }

  function normalizeWebTarget(value) {
    var target = String(value || "").trim();
    return /^https?:\/\//i.test(target) ? target : ("https://" + target);
  }

  function hostnameForLookup(value) {
    try { return new URL(normalizeWebTarget(value)).hostname; } catch (error) { return value; }
  }

  function setText(id, value) { byId(id).textContent = value == null || value === "" ? "-" : String(value); }

  function setVisible(id, visible) { byId(id).style.display = visible ? "block" : "none"; }

  function resetMainCards() {
    ["vt-extra-label-1", "vt-extra-label-2", "vt-extra-label-3", "vt-extra-value-1", "vt-extra-value-2", "vt-extra-value-3"].forEach(function (id) { setText(id, ""); });
    setText("vt-score", "-");
    byId("vt-score").className = "val";
    setText("sho-org", "-"); setText("sho-ports", "-"); setText("sho-vulns", "-");
    setText("ab-score", "-"); setText("ab-reports", "-"); setText("ab-isp", "-"); setText("ab-tor", "-");
  }

  function displayVirusTotal(vt) {
    var stats, total, malicious, attr, scoreEl;
    if (!vt || !vt.found) {
      setText("vt-score", vt && vt.error ? vt.error : "Not found in VT");
      return;
    }
    attr = vt.attributes || {};
    stats = attr.last_analysis_stats || {};
    total = Object.keys(stats).reduce(function (sum, key) { return sum + Number(stats[key] || 0); }, 0);
    malicious = Number(stats.malicious || 0);
    scoreEl = byId("vt-score");
    scoreEl.textContent = malicious + " / " + total + " (Rep: " + Number(attr.reputation || 0) + ")";
    scoreEl.className = malicious > 0 ? "val alert" : "val clean";

    if (currentType === "hash") {
      setText("vt-extra-label-1", "Type:"); setText("vt-extra-value-1", attr.type_description || "-");
      setText("vt-extra-label-2", "Name:"); setText("vt-extra-value-2", attr.meaningful_name || "-");
      setText("vt-extra-label-3", "Threat:");
      setText("vt-extra-value-3", attr.popular_threat_classification && attr.popular_threat_classification.suggested_threat_label ? attr.popular_threat_classification.suggested_threat_label : "None");
    } else if (currentType === "ip") {
      setText("vt-extra-label-1", "Country:"); setText("vt-extra-value-1", attr.country || "-");
      setText("vt-extra-label-2", "ASN Owner:"); setText("vt-extra-value-2", attr.as_owner || "-");
    }
  }

  function displayShodan(data) {
    if (!data) return;
    if (data.error) { setText("sho-org", data.error); return; }
    setText("sho-org", data.org || data.isp || "Unknown");
    setText("sho-ports", Array.isArray(data.ports) && data.ports.length ? data.ports.join(", ") : "None");
    var vulns = data.vulns ? Object.keys(data.vulns) : [];
    setText("sho-vulns", vulns.length ? vulns.join(", ") : "None detected");
    byId("sho-vulns").className = vulns.length ? "val alert" : "val clean";
  }

  function displayAbuse(data) {
    var scoreEl;
    if (!data) return;
    if (data.error) { setText("ab-score", data.error); return; }
    scoreEl = byId("ab-score");
    scoreEl.textContent = Number(data.abuseConfidenceScore || 0) + "%";
    scoreEl.className = Number(data.abuseConfidenceScore || 0) > 0 ? "val alert" : "val clean";
    setText("ab-reports", data.totalReports == null ? "-" : data.totalReports);
    setText("ab-isp", data.isp || "Unknown");
    setText("ab-tor", data.isTor ? "YES" : "No");
  }

  function revokeScreenshot() {
    if (triageScreenshotObjectUrl) {
      URL.revokeObjectURL(triageScreenshotObjectUrl);
      triageScreenshotObjectUrl = null;
    }
  }

  function setTriageIdle() {
    revokeScreenshot();
    triageSampleId = "";
    triageSubmittedTarget = "";
    setVisible("triage-idle", true);
    setVisible("triage-loading", false);
    setVisible("triage-results", false);
    setVisible("triage-error", false);
    setText("triage-target", normalizeWebTarget(currentIoc));
    setVisible("triage-screenshot", false);
    byId("triage-screenshot").removeAttribute("src");
    setText("triage-screenshot-status", "Screenshot not available.");
    byId("triage-behavioral").innerHTML = "";
  }

  function showTriageLoading(message, subtext) {
    setVisible("triage-idle", false);
    setVisible("triage-results", false);
    setVisible("triage-error", false);
    setVisible("triage-loading", true);
    setText("triage-loading-text", message);
    setText("triage-loading-subtext", subtext || "");
  }

  function showTriageError(message) {
    setVisible("triage-loading", false);
    setVisible("triage-results", false);
    setVisible("triage-idle", true);
    setVisible("triage-error", true);
    setText("triage-error", message);
  }

  function showTriageResults() {
    setVisible("triage-loading", false);
    setVisible("triage-idle", false);
    setVisible("triage-error", false);
    setVisible("triage-results", true);
  }

  async function waitForTriage(sampleId) {
    var attempt, sample, status;
    var messages = {
      pending: "Queued / static analysis in progress...",
      static_analysis: "Static analysis in progress...",
      scheduled: "Sandbox run scheduled...",
      running: "Sandbox is running the target...",
      processing: "Sandbox finished. Generating reports..."
    };
    for (attempt = 0; attempt < 240; attempt += 1) {
      sample = await apiFetch("/api/triage/status?id=" + encodeURIComponent(sampleId));
      status = sample.status || "unknown";
      if (status === "reported") return sample;
      if (status === "failed") throw new Error("Triage analysis failed.");
      showTriageLoading(messages[status] || ("Triage status: " + status), "Sample ID: " + sampleId);
      await sleep(5000);
    }
    throw new Error("Timed out waiting for Triage after approximately 20 minutes.");
  }

  function collectTags(summary, overview) {
    var tags = new Set();
    Object.values((summary && summary.tasks) || {}).forEach(function (task) {
      (task.tags || []).forEach(function (tag) { tags.add(tag); });
    });
    ((overview && overview.targets) || []).forEach(function (target) {
      (target.tags || []).forEach(function (tag) { tags.add(tag); });
    });
    return Array.from(tags);
  }

  function collectFamilies(overview) {
    var families = new Set();
    ((overview && overview.targets) || []).forEach(function (target) {
      (target.family || []).forEach(function (family) { families.add(family); });
      (target.tags || []).forEach(function (tag) {
        if (typeof tag === "string" && tag.indexOf("family:") === 0) families.add(tag.slice(7));
      });
    });
    ((overview && overview.extracted) || []).forEach(function (item) {
      if (item && item.config && item.config.family) families.add(item.config.family);
    });
    return Array.from(families);
  }

  function collectSignatures(overview) {
    var seen = new Set();
    var result = [];
    ((overview && overview.targets) || []).forEach(function (target) {
      (target.signatures || []).forEach(function (sig) {
        var key = String(sig.name || sig.label || "") + "|" + String(sig.desc || "");
        if (!seen.has(key)) { seen.add(key); result.push(sig); }
      });
    });
    return result;
  }

  function appendBehavioralReports(reports) {
    var container = byId("triage-behavioral");
    var entries = Object.entries(reports || {});
    container.innerHTML = "";
    if (!entries.length) {
      var empty = document.createElement("div");
      empty.className = "muted";
      empty.textContent = "No behavioral report was available.";
      container.appendChild(empty);
      return;
    }
    entries.forEach(function (entry) {
      var details = document.createElement("details");
      var summary = document.createElement("summary");
      var pre = document.createElement("pre");
      summary.textContent = "Full Behavioral Report: " + entry[0];
      pre.className = "json";
      pre.textContent = JSON.stringify(entry[1], null, 2);
      details.appendChild(summary);
      details.appendChild(pre);
      container.appendChild(details);
    });
  }

  async function loadTriageScreenshot(sampleId) {
    var response = await fetch(requireWorkerUrl() + "/api/triage/screenshot?id=" + encodeURIComponent(sampleId));
    if (!response.ok) return false;
    var blob = await response.blob();
    if (!blob.type || blob.type.indexOf("image/") !== 0) return false;
    revokeScreenshot();
    triageScreenshotObjectUrl = URL.createObjectURL(blob);
    byId("triage-screenshot").src = triageScreenshotObjectUrl;
    setVisible("triage-screenshot", true);
    setText("triage-screenshot-status", "");
    return true;
  }

  function displayTriageResults(data) {
    var summary = data.summary || {};
    var overview = data.overview || null;
    var tags = collectTags(summary, overview);
    var families = collectFamilies(overview);
    var signatures = collectSignatures(overview);
    var score = summary.score != null ? summary.score : (overview && overview.analysis && overview.analysis.score != null ? overview.analysis.score : null);
    var scoreEl = byId("triage-score");

    setText("triage-status", summary.status || "reported");
    setText("triage-submitted-target", triageSubmittedTarget || summary.target || currentIoc);
    setText("triage-id", triageSampleId);
    setText("triage-tags", tags.length ? tags.join(", ") : "None");
    setText("triage-families", families.length ? families.join(", ") : "None identified");
    scoreEl.textContent = typeof score === "number" ? (score + " / 10") : "N/A";
    scoreEl.className = typeof score === "number" ? (score > 0 ? "val alert" : "val clean") : "val";

    var list = byId("triage-signatures");
    list.innerHTML = "";
    if (signatures.length) {
      signatures.forEach(function (sig) {
        var li = document.createElement("li");
        li.textContent = (sig.name || sig.label || "Signature") + (typeof sig.score === "number" ? (" [score " + sig.score + "]") : "") + (sig.desc ? (" — " + sig.desc) : "");
        list.appendChild(li);
      });
    } else {
      var liEmpty = document.createElement("li");
      liEmpty.textContent = "No signatures reported.";
      list.appendChild(liEmpty);
    }

    byId("triage-overview").textContent = overview ? JSON.stringify(overview, null, 2) : "Overview report unavailable.";
    byId("triage-summary").textContent = JSON.stringify(summary, null, 2);
    byId("triage-urlscan").textContent = data.urlscan ? JSON.stringify(data.urlscan, null, 2) : "URLScan report unavailable.";
    appendBehavioralReports(data.behavioralReports || {});
    showTriageResults();
  }

  async function runTriageSubmission() {
    var target;
    var submission;
    var full;
    if (!currentIoc || (currentType !== "url" && currentType !== "domain")) {
      updateStatus("Triage sandbox requires a URL or domain.");
      return;
    }
    target = normalizeWebTarget(currentIoc);
    if (!confirm("Submit this target to the Triage public sandbox?\n\n" + target + "\n\nDo not submit internal, confidential, authenticated, or token-containing URLs.")) return;

    byId("triage-submit-btn").disabled = true;
    try {
      triageSubmittedTarget = target;
      showTriageLoading("Submitting target to Triage...", target);
      submission = await apiFetch("/api/triage/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target })
      });
      if (!submission.id) throw new Error("Triage did not return a sample ID.");
      triageSampleId = submission.id;
      await waitForTriage(triageSampleId);
      showTriageLoading("Analysis reported. Fetching complete Triage results...", "Sample ID: " + triageSampleId);
      full = await apiFetch("/api/triage/full?id=" + encodeURIComponent(triageSampleId));
      displayTriageResults(full);
      try { await loadTriageScreenshot(triageSampleId); } catch (error) { console.warn("Screenshot unavailable", error); }
      updateStatus("Triage analysis complete for " + defang(target));
    } catch (error) {
      console.error(error);
      showTriageError(error.message);
      updateStatus("Triage error: " + error.message);
    } finally {
      byId("triage-submit-btn").disabled = false;
    }
  }

  async function runAnalysis(ioc) {
    var result;
    currentIoc = String(ioc || "").trim();
    if (!currentIoc) return;
    resetMainCards();
    updateStatus("Querying intelligence...");
    try {
      result = await apiFetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: currentIoc })
      });
      currentType = result.type || "unknown";
      setVisible("vt-card", true);
      setVisible("shodan-card", currentType === "ip");
      setVisible("abuse-card", currentType === "ip");
      setVisible("triage-card", currentType === "url" || currentType === "domain");
      displayVirusTotal(result.virustotal);
      if (currentType === "ip") {
        displayShodan(result.shodan);
        displayAbuse(result.abuseipdb);
      }
      if (currentType === "url" || currentType === "domain") setTriageIdle();
      updateStatus("Analysis complete for " + defang(currentIoc));
    } catch (error) {
      console.error(error);
      updateStatus("Analysis error: " + error.message);
    }
  }

  function openCurrentInVirusTotal() {
    var url;
    if (!currentIoc) return;
    url = "https://www.virustotal.com/gui/search/" + encodeURIComponent(currentIoc);
    if (currentType === "ip") url = "https://www.virustotal.com/gui/ip-address/" + encodeURIComponent(currentIoc);
    else if (currentType === "domain") url = "https://www.virustotal.com/gui/domain/" + encodeURIComponent(hostnameForLookup(currentIoc));
    else if (currentType === "hash") url = "https://www.virustotal.com/gui/file/" + encodeURIComponent(currentIoc);
    window.open(url, "_blank", "noopener,noreferrer");
  }

  function copyReport() {
    var report;
    if (!currentIoc) return;
    report = "=== THREAT INTEL TRIAGE ===\nIndicator: " + defang(currentIoc) + "\nType: " + currentType + "\n\n[VirusTotal]\nDetection: " + byId("vt-score").textContent + "\n";
    [1,2,3].forEach(function (n) {
      var label = byId("vt-extra-label-" + n).textContent;
      var value = byId("vt-extra-value-" + n).textContent;
      if (label || value) report += label + " " + value + "\n";
    });
    if (currentType === "ip") {
      report += "\n[Shodan]\nOrg: " + byId("sho-org").textContent + "\nPorts: " + byId("sho-ports").textContent + "\nVulns: " + byId("sho-vulns").textContent + "\n";
      report += "\n[AbuseIPDB]\nConfidence: " + byId("ab-score").textContent + "\nReports: " + byId("ab-reports").textContent + "\nISP: " + byId("ab-isp").textContent + "\nTor: " + byId("ab-tor").textContent + "\n";
    }
    if ((currentType === "domain" || currentType === "url") && triageSampleId) {
      report += "\n[Triage Sandbox]\nSubmitted: " + defang(triageSubmittedTarget) + "\nStatus: " + byId("triage-status").textContent + "\nScore: " + byId("triage-score").textContent + "\nFamilies: " + byId("triage-families").textContent + "\nTags: " + byId("triage-tags").textContent + "\nSample ID: " + triageSampleId + "\n";
    }
    navigator.clipboard.writeText(report).then(function () { updateStatus("Report copied to clipboard."); });
  }

  function saveWorkerUrl() {
    var value = normalizeWorkerUrl(byId("worker-url").value);
    if (!value) { updateStatus("Enter your Cloudflare Worker URL."); return; }
    try { new URL(value); } catch (error) { updateStatus("Invalid Worker URL."); return; }
    localStorage.setItem("socIntelWorkerUrl", value);
    updateStatus("Backend URL saved in this browser.");
  }

  byId("worker-url").value = getWorkerUrl();
  byId("save-worker-btn").addEventListener("click", saveWorkerUrl);
  byId("search-btn").addEventListener("click", function () { runAnalysis(byId("ioc-input").value); });
  byId("ioc-input").addEventListener("keydown", function (event) { if (event.key === "Enter") runAnalysis(event.target.value); });
  byId("copy-btn").addEventListener("click", copyReport);
  byId("triage-submit-btn").addEventListener("click", runTriageSubmission);
  byId("triage-run-again-btn").addEventListener("click", function () { setTriageIdle(); runTriageSubmission(); });
  byId("triage-open-btn").addEventListener("click", function () { if (triageSampleId) window.open("https://tria.ge/" + encodeURIComponent(triageSampleId), "_blank", "noopener,noreferrer"); });
  byId("pivot-vt").addEventListener("click", openCurrentInVirusTotal);
  byId("pivot-ab").addEventListener("click", function () { if (currentType === "ip") window.open("https://www.abuseipdb.com/check/" + encodeURIComponent(currentIoc), "_blank", "noopener,noreferrer"); });
  byId("pivot-sh").addEventListener("click", function () { if (currentType === "ip") window.open("https://www.shodan.io/host/" + encodeURIComponent(currentIoc), "_blank", "noopener,noreferrer"); });
  window.addEventListener("unload", revokeScreenshot);
}());
