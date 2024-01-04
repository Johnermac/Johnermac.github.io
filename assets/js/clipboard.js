// Clipboard
// This makes the button blink 250 milliseconds

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function buttonBlink(btn, style) {
  btn.classList.remove("btn-light");
  btn.classList.add(style);
  await sleep(250); // Blink ms
  btn.classList.remove(style);
  btn.classList.add("btn-light");
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
  btn.innerHTML = "<i class='far fa-copy'></i>"; // Updated button content

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

// Add CSS styles dynamically
var styles = `
  .window-container {
    position: relative;
    background-color: #141414; /* Darker background color */
    border-radius: 0px;
    margin-bottom: 0px;
  }

  .window-header {
    background-color: #454545;
    padding: 0px;
    border-bottom: 0px solid #ddd;
    text-align: right;
  }

  .btn {
    display: inline-block;
    padding: 5px 8px; /* Adjusted button size */
    margin-bottom: 0;
    font-size: 12px; /* Adjusted font size */
    font-weight: 400;
    line-height: 1.42857143;
    text-align: center;
    white-space: nowrap;
    vertical-align: middle;
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 1px;
  }

  .btn--primary {
    color: #fff;
    background-color: #337ab7;
    border-color: #2e6da4;
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
  buttonBlink(e.trigger, "btn--success");

  // Change button content to "Copied!"
  e.trigger.innerHTML = "<i class='fas fa-check'></i>";

  // Reset button content after a delay (e.g., 1500 milliseconds)
  setTimeout(function () {
    e.trigger.innerHTML = "<i class='far fa-copy'></i>";
  }, 1500);
});

clipboards.on("error", function (e) {
  e.clearSelection();
  buttonBlink(e.trigger, "btn--danger");

  // Change button content to "Error!"
  e.trigger.innerHTML = "<i class='far fa-times-circle'></i>";

  // Reset button content after a delay (e.g., 1500 milliseconds)
  setTimeout(function () {
    e.trigger.innerHTML = "<i class='far fa-copy'></i>";
  }, 1500);
});
// Finish
