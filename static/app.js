async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function getJSON(url) {
  return fetch(url).then(async (response) => {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  });
}

function element(id) {
  return document.getElementById(id);
}

function setError(id, message) {
  const box = element(id);
  if (!box) return;
  box.textContent = message || "";
  box.classList.toggle("hidden", !message);
}

function setBusy(button, busy, busyText, idleText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : idleText;
}

function saveScan(kind, label, hostname) {
  try {
    const history = JSON.parse(localStorage.getItem("signalforge-history") || "[]");
    history.unshift({ kind, label, hostname: hostname || "", timestamp: Date.now() });
    localStorage.setItem("signalforge-history", JSON.stringify(history.slice(0, 12)));
  } catch (error) {
    console.warn("Local scan history is unavailable.", error);
  }
}

function renderHistory() {
  const list = element("recentScans");
  if (!list) return;
  try {
    const history = JSON.parse(localStorage.getItem("signalforge-history") || "[]");
    element("scanCount").textContent = String(history.length).padStart(2, "0");
    list.replaceChildren();
    if (!history.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.innerHTML = "<span>◷</span><p>No scans yet</p><small>Your scan summaries will appear here, stored only in this browser.</small>";
      list.appendChild(empty);
      return;
    }
    history.slice(0, 5).forEach((item) => {
      const row = document.createElement("div");
      row.className = "recent-row";
      const symbol = document.createElement("span");
      symbol.className = "recent-symbol";
      symbol.textContent = item.kind === "URL" ? "⌁" : "✉";
      const detail = document.createElement("span");
      detail.className = "recent-detail";
      const title = document.createElement("strong");
      title.textContent = item.hostname || item.kind + " analysis";
      const time = document.createElement("small");
      time.textContent = new Date(item.timestamp).toLocaleString();
      detail.append(title, time);
      const verdict = document.createElement("span");
      const verdictColor = item.label === "malicious" || item.label === "high"
        ? "text-danger" : item.label === "medium" ? "text-warning" : "text-safe";
      verdict.className = "recent-verdict " + verdictColor;
      verdict.textContent = item.label.toUpperCase();
      row.append(symbol, detail, verdict);
      list.appendChild(row);
    });
  } catch (error) {
    console.warn("Could not read local scan history.", error);
  }
}

function severityClass(severity) {
  return severity === "high" ? "verdict-high" : severity === "medium" ? "verdict-medium" : "verdict-low";
}

function renderUrlItem(result, container) {
  const row = document.createElement("div");
  row.className = "url-result-row";
  const details = document.createElement("div");
  details.className = "url-result-detail";
  const address = document.createElement("strong");
  address.textContent = result.url;
  const explanation = document.createElement("small");
  explanation.textContent = result.error || result.explanation || "";
  details.append(address, explanation);
  const badge = document.createElement("span");
  badge.className = "risk-badge risk-" + (
    result.label === "malicious" ? "high" : result.label === "invalid" ? "medium" : "low"
  );
  badge.textContent = result.label.toUpperCase();
  row.append(details, badge);
  container.appendChild(row);
}

const analyzeButton = element("analyzeBtn");
if (analyzeButton) {
  analyzeButton.addEventListener("click", async () => {
    const button = analyzeButton;
    const text = element("emailText").value;
    setError("emailError", "");
    setBusy(button, true, "Analyzing…", "Analyze message →");
    try {
      const data = await postJSON("/api/analyze", { text });
      element("verdictBanner").textContent = data.verdict;
      element("verdictBanner").className = "verdict-banner " + severityClass(data.severity);
      element("spamLabel").textContent = data.spam_module.label.toUpperCase();
      element("spamProb").textContent = (data.spam_module.probability_spam * 100).toFixed(1) + "%";
      element("spamMeter").style.width = (data.spam_module.probability_spam * 100) + "%";
      element("urlCount").textContent = `${data.urls_analyzed} / ${data.urls_found}`;
      element("analysisTime").textContent = new Date().toLocaleTimeString();
      element("analysisNote").textContent = data.analysis_note;

      const urls = element("urlList");
      urls.replaceChildren();
      if (data.url_module.length) data.url_module.forEach((result) => renderUrlItem(result, urls));
      else {
        const empty = document.createElement("p");
        empty.className = "empty-inline";
        empty.textContent = "No links found in this message.";
        urls.appendChild(empty);
      }

      const signals = element("emailSignals");
      signals.replaceChildren();
      data.email_signals.forEach((signal) => {
        const row = document.createElement("div");
        row.className = "signal-item";
        const badge = document.createElement("span");
        badge.className = "risk-badge risk-" + (signal.severity === "high" ? "high" : "medium");
        badge.textContent = signal.severity.toUpperCase();
        const textBlock = document.createElement("span");
        const title = document.createElement("strong");
        title.textContent = signal.title;
        const detail = document.createElement("small");
        detail.textContent = signal.detail;
        textBlock.append(title, detail);
        row.append(badge, textBlock);
        signals.appendChild(row);
      });
      element("noEmailSignals").classList.toggle("hidden", data.email_signals.length > 0);
      element("analyzeResult").classList.remove("hidden");
      saveScan("EMAIL", data.severity, "");
    } catch (error) {
      setError("emailError", error.message);
    } finally {
      setBusy(button, false, "", "Analyze message →");
    }
  });
}

const urlButton = element("urlBtn");
if (urlButton) {
  urlButton.addEventListener("click", async () => {
    const button = urlButton;
    const url = element("urlInput").value;
    setError("urlError", "");
    setBusy(button, true, "Scanning…", "Scan →");
    try {
      const data = await postJSON("/api/check-url", { url });
      const box = element("urlResult");
      box.replaceChildren();
      renderUrlItem(data, box);
      const metadata = document.createElement("div");
      metadata.className = "url-metadata";
      const score = document.createElement("span");
      score.textContent = `Effective risk score ${(data.probability_malicious * 100).toFixed(1)}%`;
      const modelScore = document.createElement("span");
      modelScore.textContent = `Raw model score ${(data.model_probability_malicious * 100).toFixed(1)}%`;
      metadata.append(score, modelScore);
      box.appendChild(metadata);
      const signals = document.createElement("div");
      signals.className = "url-signals";
      data.signals.forEach((signal) => {
        const chip = document.createElement("span");
        chip.textContent = signal;
        signals.appendChild(chip);
      });
      box.appendChild(signals);
      box.classList.remove("hidden");
      saveScan("URL", data.label, data.hostname);
    } catch (error) {
      setError("urlError", error.message);
    } finally {
      setBusy(button, false, "", "Scan →");
    }
  });
}

const batchButton = element("batchBtn");
if (batchButton) {
  batchButton.addEventListener("click", async () => {
    const button = batchButton;
    const urls = element("batchUrls").value.split(/\r?\n/).filter((line) => line.trim());
    setError("batchError", "");
    setBusy(button, true, "Scanning…", "Scan list →");
    try {
      const data = await postJSON("/api/check-urls", { urls });
      const box = element("batchResult");
      box.replaceChildren();
      const summary = document.createElement("p");
      summary.className = "batch-summary";
      summary.textContent = `${data.scanned} scanned · ${data.malicious} flagged · ${data.invalid} invalid`;
      box.appendChild(summary);
      data.results.forEach((result) => renderUrlItem(result, box));
      box.classList.remove("hidden");
      data.results.filter((result) => result.label !== "invalid").forEach((result) => saveScan("URL", result.label, result.hostname));
    } catch (error) {
      setError("batchError", error.message);
    } finally {
      setBusy(button, false, "", "Scan list →");
    }
  });
}

const clearHistory = element("clearHistoryBtn");
if (clearHistory) {
  clearHistory.addEventListener("click", () => {
    localStorage.removeItem("signalforge-history");
    renderHistory();
  });
  renderHistory();
}

const passwordInput = element("passwordInput");
if (passwordInput) {
  const updatePasswordFeedback = () => {
    const password = passwordInput.value;
    const tips = [];
    let score = 0;
    if (password.length >= 15) score += 2;
    else if (password.length >= 10) score += 1;
    else tips.push("Aim for at least 15 characters; a longer passphrase is easier to remember.");
    const characterGroups = [
      /[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^a-zA-Z0-9]/.test(password),
    ].filter(Boolean).length;
    if (characterGroups >= 3) score += 1;
    else tips.push("Mix character types, or use several unrelated words.");
    if (/(.)\1{2,}/.test(password) || /password|qwerty|letmein|admin|welcome|123456/i.test(password)) {
      score -= 2;
      tips.push("Avoid common words, keyboard patterns and repeated characters.");
    }
    if (password && !tips.length) tips.push("Good start. Use it only once and consider a password manager.");
    if (!password) tips.push("Use a unique passphrase of 15+ characters.");
    const level = !password ? "Waiting for input" : score <= 0 ? "Needs work" : score < 2 ? "Fair" : score < 3 ? "Good" : "Strong";
    element("passwordScore").textContent = level;
    element("passwordMeter").style.width = `${password ? Math.max(8, Math.min(100, (score + 1) * 25)) : 0}%`;
    element("passwordMeter").className = score >= 3 ? "meter-strong" : score >= 1 ? "meter-fair" : "meter-weak";
    const list = element("passwordTips");
    list.replaceChildren();
    tips.forEach((tip) => {
      const item = document.createElement("li");
      item.textContent = tip;
      list.appendChild(item);
    });
  };
  passwordInput.addEventListener("input", updatePasswordFeedback);
  element("togglePassword").addEventListener("click", () => {
    const showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    element("togglePassword").textContent = showing ? "Show" : "Hide";
    element("togglePassword").setAttribute("aria-label", showing ? "Show password" : "Hide password");
  });
}

const modelCards = element("modelCards");
if (modelCards) {
  getJSON("/api/model-stats").then((data) => {
    data.models.forEach((model, index) => {
      const card = document.createElement("article");
      card.className = "panel model-card";
      const heading = document.createElement("div");
      heading.className = "model-heading";
      const eyebrow = document.createElement("p");
      eyebrow.className = "eyebrow";
      eyebrow.textContent = `MODULE 0${index + 1}`;
      const name = document.createElement("h2");
      name.textContent = model.name.replace("LogisticRegression", "Logistic Regression");
      const task = document.createElement("p");
      task.className = "field-hint";
      task.textContent = model.task;
      heading.append(eyebrow, name, task);
      const metrics = document.createElement("div");
      metrics.className = "model-metrics";
      [
        ["F1 SCORE", `${(model.f1 * 100).toFixed(1)}%`],
        ["ROC-AUC", model.roc_auc.toFixed(3)],
        ["TRAIN ROWS", model.training_records.toLocaleString()],
        ["TEST ROWS", model.test_records.toLocaleString()],
      ].forEach(([label, value]) => {
        const item = document.createElement("div");
        item.innerHTML = `<small>${label}</small><strong>${value}</strong>`;
        metrics.appendChild(item);
      });
      card.append(heading, metrics);
      modelCards.appendChild(card);
    });

    data.datasets.forEach((dataset) => {
      const card = document.createElement("div");
      card.className = "dataset-card";
      const title = document.createElement("strong");
      title.textContent = dataset.name;
      const count = document.createElement("span");
      count.textContent = `${dataset.records.toLocaleString()} records`;
      const classes = document.createElement("small");
      classes.textContent = dataset.classes;
      card.append(title, count, classes);
      element("datasetCards").appendChild(card);
    });
    const features = element("featureList");
    data.models[1].top_features.forEach((feature) => {
      const row = document.createElement("div");
      row.className = "feature-row";
      const label = document.createElement("span");
      label.textContent = feature.feature.replaceAll("_", " ");
      const meter = document.createElement("span");
      meter.className = "feature-meter";
      const fill = document.createElement("i");
      fill.style.width = `${Math.max(3, feature.importance * 500)}%`;
      meter.appendChild(fill);
      const value = document.createElement("small");
      value.textContent = `${(feature.importance * 100).toFixed(1)}%`;
      row.append(label, meter, value);
      features.appendChild(row);
    });
    element("modelNote").textContent = data.evaluation_note + " The URL model is a lexical baseline, not a live reputation service; dataset scores do not imply real-world certainty.";
    element("modelLoading").classList.add("hidden");
    element("modelContent").classList.remove("hidden");
  }).catch((error) => {
    element("modelLoading").classList.add("hidden");
    setError("modelError", error.message);
  });
}
