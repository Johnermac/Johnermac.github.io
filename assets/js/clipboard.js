// Clipboard
// This makes the button blink 250 milliseconds

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function buttonBlink(btn, style) {
  btn.classList.add(style);
  await sleep(250); // Blink ms
  btn.classList.remove(style);
}
// End

// Select highlighted codes
var codeChunks = document.querySelectorAll("pre.highlight");

// Loop to add buttons and create containers
codeChunks.forEach(function (codeChunk) {
  // Create window-like container
  var windowContainer = document.createElement("div");
  windowContainer.classList.add("window-container");

  // Create window header
  var windowHeader = document.createElement("div");
  windowHeader.classList.add("window-header");

  // Prepare button
  var btn = document.createElement("button");
  btn.setAttribute('type', 'button');
  btn.setAttribute('aria-label', 'Copy code');
  btn.innerHTML = "<i class='far fa-copy btn-icon' aria-hidden='true'></i><span class='btn-label'>Copy code</span>"; // Icon + label

  // Inline styling for the button
  btn.classList.add("btn", "btn--primary", "btn-sm"); // Added "btn-sm" for smaller button size

  // Identifier for ClipboardJS
  btn.setAttribute("data-clipboard-text", codeChunk.innerText.trim());

  // Insert button into the window header
  windowHeader.appendChild(btn);

  // Insert window header into the window container
  windowContainer.appendChild(windowHeader);

  // Insert window container before the code block
  codeChunk.parentNode.insertBefore(windowContainer, codeChunk);

  // Move the code block inside the window container
  windowContainer.appendChild(codeChunk);
});
// End

var styles = `
.window-container {
  position: relative;
  background-color: #141414;
  border-radius: 0;
  margin-bottom: 0;
}

/* ---------- HEADER SAME AS CODE BLOCK ---------- */
.window-header {
  background: inherit; /* matches code block */

  display: flex;
  align-items: center;
  justify-content: flex-end;

  min-height: 26px;
  padding: 2px 6px;

  border-bottom: none;
}

/* ---------- PERFECTLY CENTERED THIN BUTTON ---------- */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center; /* ensures horizontal centering */

  gap: 0.35rem;

  padding: 2px 7px;
  min-height: 20px; /* prevents font pushing height */

  font-size: 12px;
  font-weight: 450;
  line-height: 1; /* critical for vertical centering */

  white-space: nowrap;
  cursor: pointer;

  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 5px;

  background: rgba(255,255,255,0.04);
  color: #e6e6e6;

  transition:
    background .16s ease,
    border-color .16s ease,
    transform .05s ease,
    opacity .16s ease;

  opacity: 0.92;
}

.btn:hover {
  background: rgba(255,255,255,0.08);
  border-color: rgba(255,255,255,0.14);
  opacity: 1;
}

.btn:active {
  transform: scale(0.96);
}

/* ---------- ICON + LABEL BALANCE ---------- */
.btn-icon {
  font-size: 0.9rem;
  line-height: 1;
  display: flex;
  align-items: center;
}

.btn-label {
  display: flex;
  align-items: center;
  line-height: 1;
}

/* ---------- STATES ---------- */
.btn.is--copied {
  background: rgba(22,163,74,0.9);
  color: #fff;
  border-color: transparent;
}

.btn.is--error {
  background: rgba(220,38,38,0.9);
  color: #fff;
  border-color: transparent;
}
`;




var styleTag = document.createElement("style");
styleTag.innerHTML = styles;
document.head.appendChild(styleTag);

// Copy to clipboard
var clipboards = new ClipboardJS(".btn", {
  target: function (trigger) {
    return trigger.parentElement.nextElementSibling;
  }
});

// Messages and make the button blink
clipboards.on("success", function (e) {
  e.clearSelection();
  // brief blink then show persistent copied state
  buttonBlink(e.trigger, "btn--success");

  e.trigger.classList.add('is--copied');
  e.trigger.setAttribute('aria-pressed', 'true');
  e.trigger.innerHTML = "<i class='fas fa-check btn-icon' aria-hidden='true'></i><span class='btn-label'>Copied!</span>";

  // Reset button content after a delay
  setTimeout(function () {
    e.trigger.classList.remove('is--copied');
    e.trigger.setAttribute('aria-pressed', 'false');
    e.trigger.innerHTML = "<i class='far fa-copy btn-icon' aria-hidden='true'></i><span class='btn-label'>Copy code</span>";
  }, 1500);
});

clipboards.on("error", function (e) {
  e.clearSelection();
  buttonBlink(e.trigger, "btn--danger");

  e.trigger.classList.add('is--error');
  e.trigger.setAttribute('aria-pressed', 'true');
  e.trigger.innerHTML = "<i class='far fa-times-circle btn-icon' aria-hidden='true'></i><span class='btn-label'>Error</span>";

  setTimeout(function () {
    e.trigger.classList.remove('is--error');
    e.trigger.setAttribute('aria-pressed', 'false');
    e.trigger.innerHTML = "<i class='far fa-copy btn-icon' aria-hidden='true'></i><span class='btn-label'>Copy code</span>";
  }, 1500);
});
// Finish
