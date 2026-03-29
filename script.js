const DIGITS = "0123456789";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SYMBOLS = "%*)?@#$~";
const MAX_HISTORY = 10;
const AUTO_GENERATE_DEBOUNCE_MS = 150;
const EMPTY_HISTORY_TEXT = "Пока пусто";

const hasDom = typeof document !== "undefined";

const form = hasDom ? document.getElementById("generator-form") : null;
const copyBtn = hasDom ? document.getElementById("copyBtn") : null;
const leakCheckBtn = hasDom ? document.getElementById("leakCheckBtn") : null;
const output = hasDom ? document.getElementById("passwordOutput") : null;
const message = hasDom ? document.getElementById("message") : null;
const leakMessage = hasDom ? document.getElementById("leakMessage") : null;
const securityNote = hasDom ? document.getElementById("securityNote") : null;
const strengthText = hasDom ? document.getElementById("strengthText") : null;
const strengthFill = hasDom ? document.getElementById("strengthFill") : null;
const strengthBar = hasDom ? document.querySelector(".strength__bar") : null;
const historyList = hasDom ? document.getElementById("historyList") : null;

const controls = {
  useDigits: hasDom ? document.getElementById("useDigits") : null,
  useLower: hasDom ? document.getElementById("useLower") : null,
  useUpper: hasDom ? document.getElementById("useUpper") : null,
  useSymbols: hasDom ? document.getElementById("useSymbols") : null,
  noRepeat: hasDom ? document.getElementById("noRepeat") : null,
  length: hasDom ? document.getElementById("length") : null
};

let history = [];
let autoTimer = null;
let lastPassword = "";

function hasCryptoSupport() {
  return typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function";
}

function hasSubtleCryptoSupport() {
  return typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.digest === "function";
}

function secureRandomInt(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error("Некорректный диапазон случайного числа.");
  }

  const uint32Max = 0x100000000;
  const bucketSize = Math.floor(uint32Max / maxExclusive);
  const maxUnbiased = bucketSize * maxExclusive;
  const randomBuffer = new Uint32Array(1);

  let candidate = 0;
  do {
    crypto.getRandomValues(randomBuffer);
    candidate = randomBuffer[0];
  } while (candidate >= maxUnbiased);

  return candidate % maxExclusive;
}

function buildCharset(config) {
  let charset = "";
  if (config.useDigits) charset += DIGITS;
  if (config.useLower) charset += LOWER;
  if (config.useUpper) charset += UPPER;
  if (config.useSymbols) charset += SYMBOLS;
  return charset;
}

// Public contract: generatePassword(config) -> { ok, password?, error? }
function generatePassword(config) {
  if (!hasCryptoSupport()) {
    return { ok: false, error: "Без crypto.getRandomValues нельзя безопасно сгенерировать пароль." };
  }

  const charset = buildCharset(config);
  if (!charset.length) {
    return { ok: false, error: "Выберите хотя бы один тип символов." };
  }

  if (config.noRepeat && config.length > charset.length) {
    return {
      ok: false,
      error: `При запрете повторов максимальная длина: ${charset.length} для текущего набора символов.`
    };
  }

  let password = "";

  if (config.noRepeat) {
    const pool = charset.split("");
    for (let i = 0; i < config.length; i += 1) {
      const randomIndex = secureRandomInt(pool.length);
      password += pool[randomIndex];
      pool.splice(randomIndex, 1);
    }
  } else {
    for (let i = 0; i < config.length; i += 1) {
      password += charset[secureRandomInt(charset.length)];
    }
  }

  return { ok: true, password };
}

function getConfig() {
  if (!controls.length) {
    return {
      length: 12,
      useDigits: true,
      useLower: true,
      useUpper: true,
      useSymbols: false,
      noRepeat: false
    };
  }

  return {
    length: Number(controls.length.value),
    useDigits: controls.useDigits.checked,
    useLower: controls.useLower.checked,
    useUpper: controls.useUpper.checked,
    useSymbols: controls.useSymbols.checked,
    noRepeat: controls.noRepeat.checked
  };
}

function countEnabledClasses(config) {
  return [config.useDigits, config.useLower, config.useUpper, config.useSymbols].filter(Boolean).length;
}

function evaluateStrength(password, config) {
  let score = 0;
  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 15;
  if (password.length >= 16) score += 15;
  score += Math.min(countEnabledClasses(config) * 12, 48);

  if (config.noRepeat && password.length >= 10) {
    score += 5;
  }

  score = Math.max(0, Math.min(100, score));

  let label = "Слабый";
  if (score >= 70) {
    label = "Сильный";
  } else if (score >= 45) {
    label = "Средний";
  }

  return { score, label };
}

function setMessage(text, type = "") {
  if (!message) return;
  message.textContent = text;
  message.className = "message";
  if (type) {
    message.classList.add(type);
  }
}

function setLeakMessage(text, type = "") {
  if (!leakMessage) return;
  leakMessage.textContent = text;
  leakMessage.className = "message leak-message";
  if (type) {
    leakMessage.classList.add(type);
  }
}

function revealSecurityNote() {
  if (!securityNote) return;
  securityNote.hidden = false;
}

function renderHistory() {
  if (!historyList) return;

  if (!history.length) {
    historyList.innerHTML = `<li class="history-empty">${EMPTY_HISTORY_TEXT}</li>`;
    return;
  }

  historyList.innerHTML = "";
  for (const value of history) {
    const li = document.createElement("li");
    li.textContent = value;
    historyList.appendChild(li);
  }
}

function pushHistory(password) {
  history = [password, ...history.filter((entry) => entry !== password)].slice(0, MAX_HISTORY);
  renderHistory();
}

function renderStrength(password, config) {
  if (!strengthText || !strengthFill || !strengthBar) return;
  const { score, label } = evaluateStrength(password, config);
  strengthText.textContent = `${label} (${score}%)`;
  strengthFill.style.width = `${score}%`;
  strengthBar.setAttribute("aria-valuenow", String(score));
}

function handleGenerate() {
  const config = getConfig();
  const result = generatePassword(config);

  if (!result.ok) {
    if (output) output.textContent = "-";
    lastPassword = "";
    if (copyBtn) copyBtn.disabled = true;
    if (leakCheckBtn) leakCheckBtn.disabled = true;
    if (strengthText) strengthText.textContent = "-";
    if (strengthFill) strengthFill.style.width = "0%";
    if (strengthBar) strengthBar.setAttribute("aria-valuenow", "0");
    setMessage(result.error, "error");
    setLeakMessage("");
    return;
  }

  if (output) output.textContent = result.password;
  lastPassword = result.password;
  if (copyBtn) copyBtn.disabled = false;
  if (leakCheckBtn) leakCheckBtn.disabled = false;
  renderStrength(result.password, config);
  pushHistory(result.password);
  setMessage("Пароль успешно сгенерирован.", "success");
  setLeakMessage("");
}

function scheduleAutoGenerate() {
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => {
    handleGenerate();
  }, AUTO_GENERATE_DEBOUNCE_MS);
}

async function handleCopy() {
  if (!lastPassword) {
    setMessage("Сначала сгенерируйте пароль.", "error");
    return;
  }

  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
    setMessage("Clipboard API недоступен в этом браузере.", "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(lastPassword);
    setMessage("Пароль скопирован в буфер обмена.", "success");
  } catch {
    setMessage("Не удалось скопировать пароль. Проверьте разрешения браузера.", "error");
  }
}

async function sha1Hex(value) {
  if (!hasSubtleCryptoSupport()) {
    throw new Error("Web Crypto API (subtle.digest) недоступен для безопасной проверки.");
  }

  const buffer = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", buffer);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function findLeakCountByHash(fullHash, rangesText) {
  const normalizedHash = String(fullHash || "").trim().toUpperCase();
  if (normalizedHash.length < 6) return 0;

  const suffix = normalizedHash.slice(5);
  const lines = String(rangesText || "").split(/\r?\n/);

  for (const line of lines) {
    if (!line) continue;
    const [currentSuffix, countRaw] = line.split(":");
    if (currentSuffix && currentSuffix.trim().toUpperCase() === suffix) {
      const count = Number.parseInt((countRaw || "0").trim(), 10);
      return Number.isFinite(count) ? count : 0;
    }
  }

  return 0;
}

async function checkPasswordLeakWithProviders(password, options = {}) {
  const hashProvider = options.hashProvider || sha1Hex;
  const fetchProvider = options.fetchProvider || (typeof fetch === "function" ? fetch.bind(globalThis) : null);

  if (!fetchProvider) {
    throw new Error("Fetch API недоступен для проверки через HIBP.");
  }

  const fullHash = (await hashProvider(password)).toUpperCase();
  const prefix = fullHash.slice(0, 5);

  const response = await fetchProvider(`https://api.pwnedpasswords.com/range/${prefix}`, {
    method: "GET",
    headers: {
      "Add-Padding": "true"
    }
  });

  if (!response.ok) {
    throw new Error("Сервис HIBP недоступен. Попробуйте позже.");
  }

  const ranges = await response.text();
  return findLeakCountByHash(fullHash, ranges);
}

async function checkPasswordLeak(password) {
  return checkPasswordLeakWithProviders(password);
}

async function handleLeakCheck() {
  revealSecurityNote();

  if (!lastPassword) {
    setLeakMessage("Сначала сгенерируйте пароль.", "error");
    return;
  }

  setLeakMessage("Проверяем через HIBP по методу k-anonymity...", "info");

  try {
    const leakCount = await checkPasswordLeak(lastPassword);
    if (leakCount > 0) {
      setLeakMessage(`Этот пароль найден в утечках: ${leakCount} учетных записей. Рекомендуется сгенерировать новый.`, "warning");
      return;
    }

    setLeakMessage("Совпадений в известных утечках HIBP не найдено.", "success");
  } catch (error) {
    setLeakMessage(error instanceof Error ? error.message : "Не удалось проверить пароль на утечку.", "error");
  }
}

if (form) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    handleGenerate();
  });
}

for (const element of Object.values(controls)) {
  if (element) {
    element.addEventListener("change", scheduleAutoGenerate);
  }
}

if (copyBtn) {
  copyBtn.addEventListener("click", handleCopy);
}

if (leakCheckBtn) {
  leakCheckBtn.addEventListener("click", handleLeakCheck);
}

if (hasDom) {
  handleGenerate();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    generatePassword,
    sha1Hex,
    findLeakCountByHash,
    checkPasswordLeakWithProviders,
    checkPasswordLeak
  };
}
