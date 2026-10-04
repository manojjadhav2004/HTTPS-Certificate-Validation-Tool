// All text from the server (certificate fields can be attacker-controlled) is inserted with
// textContent, never innerHTML, so a hostile certificate cannot inject HTML or scripts.
const $ = (id) => document.getElementById(id);

const LAB = [
  ["Valid", 4443], ["Near expiry", 4444], ["Expired", 4445],
  ["Wrong hostname", 4446], ["Self-signed", 4447], ["Weak RSA 1024", 4448],
];

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function add(parent, tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  parent.appendChild(node);
  return node;
}

function fill(dl, rows) {
  clear(dl);
  rows.forEach(([label, value]) => {
    add(dl, "dt", label);
    add(dl, "dd", value === null || value === undefined || value === "" ? "-" : String(value));
  });
}

function showError(message) {
  $("result").hidden = false;
  $("details").hidden = true;
  $("disclaimer").textContent = "";
  const verdict = $("verdict");
  verdict.className = "verdict NOTSECURE";
  verdict.textContent = "No verdict";
  add(verdict, "small", "The certificate could not be checked.");
  const box = $("error");
  box.hidden = false;
  box.textContent = message;
}

function render(data) {
  $("result").hidden = false;
  if (data.error) {
    showError(data.error.message);
    return;
  }
  $("error").hidden = true;
  $("details").hidden = false;

  const verdict = $("verdict");
  verdict.className = "verdict " + data.verdict.replace(" ", "");
  verdict.textContent = "Final verdict: " + data.verdict;
  add(verdict, "small", data.target + ":" + data.port + " - checked " + data.checked_at);

  const reasons = $("reasons");
  clear(reasons);
  data.reasons.forEach((r) => add(reasons, "li", r));
  $("notes").textContent = (data.notes || []).join(" ");

  const table = $("checks");
  clear(table);
  data.checks.forEach((check) => {
    const row = add(table, "tr");
    add(row, "td", check.name, "name");
    const status = add(row, "td");
    add(status, "span", check.status, "badge " + check.status);
    add(row, "td", check.detail);
  });

  const c = data.certificate;
  const keySize = c.public_key_size ? c.public_key_size + " bits" : "unknown size";
  fill($("cert"), [
    ["Subject", c.subject],
    ["Issuer", c.issuer],
    ["Common name", c.common_name],
    ["Subject alternative names", c.subject_alt_names.join(", ")],
    ["Serial number", c.serial_number],
    ["Valid from", c.valid_from],
    ["Valid until", c.valid_until],
    ["Days remaining", c.days_remaining],
    ["Public key", c.public_key_type + ", " + keySize],
    ["Signature algorithm", c.signature_algorithm],
    ["SHA-256 fingerprint", c.sha256_fingerprint],
  ]);
  fill($("tls"), [
    ["Negotiated TLS version", data.tls_version],
    ["Cipher suite", data.cipher],
    ["Verified handshake", data.handshake_verified ? "Yes" : "No"],
  ]);
  $("disclaimer").textContent = data.disclaimer;
}

async function validate(target, port, useLabCa) {
  const button = $("go");
  button.disabled = true;
  button.textContent = "Checking...";
  try {
    const response = await fetch("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target, port: port, use_lab_ca: useLabCa }),
    });
    const data = await response.json();
    if (data.error) { showError(data.error.message); } else { render(data); }
  } catch (err) {
    showError("Could not reach the dashboard server: " + err);
  } finally {
    button.disabled = false;
    button.textContent = "Validate";
  }
}

$("form").addEventListener("submit", (event) => {
  event.preventDefault();
  validate($("target").value, $("port").value, $("lab-ca").checked);
});

LAB.forEach(([label, port]) => {
  const button = add($("lab-buttons"), "button", label + " (" + port + ")");
  button.type = "button";
  button.addEventListener("click", () => {
    $("target").value = "localhost";
    $("port").value = port;
    $("lab-ca").checked = true;
    validate("localhost", String(port), true);
  });
});
