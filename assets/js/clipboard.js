// Copy-to-clipboard buttons for code blocks.
// Styles live in assets/css/main.scss (.window-container / .code-copy-btn).

(function () {
  var codeChunks = document.querySelectorAll("pre.highlight");
  if (!codeChunks.length || typeof ClipboardJS === "undefined") return;

  var COPY_HTML =
    "<i class='far fa-copy btn-icon' aria-hidden='true'></i><span class='btn-label'>Copy code</span>";

  codeChunks.forEach(function (codeChunk) {
    var windowContainer = document.createElement("div");
    windowContainer.classList.add("window-container");

    var windowHeader = document.createElement("div");
    windowHeader.classList.add("window-header");

    var btn = document.createElement("button");
    btn.setAttribute("type", "button");
    btn.setAttribute("aria-label", "Copy code");
    btn.classList.add("code-copy-btn");
    btn.innerHTML = COPY_HTML;

    windowHeader.appendChild(btn);
    windowContainer.appendChild(windowHeader);
    codeChunk.parentNode.insertBefore(windowContainer, codeChunk);
    windowContainer.appendChild(codeChunk);
  });

  function flashState(btn, stateClass, html) {
    btn.classList.add(stateClass);
    btn.innerHTML = html;
    setTimeout(function () {
      btn.classList.remove(stateClass);
      btn.innerHTML = COPY_HTML;
    }, 1500);
  }

  var clipboards = new ClipboardJS(".code-copy-btn", {
    text: function (trigger) {
      return trigger
        .closest(".window-container")
        .querySelector("pre.highlight").innerText.trim();
    }
  });

  clipboards.on("success", function (e) {
    flashState(
      e.trigger,
      "is--copied",
      "<i class='fas fa-check btn-icon' aria-hidden='true'></i><span class='btn-label'>Copied!</span>"
    );
  });

  clipboards.on("error", function (e) {
    flashState(
      e.trigger,
      "is--error",
      "<i class='far fa-times-circle btn-icon' aria-hidden='true'></i><span class='btn-label'>Error</span>"
    );
  });
})();
