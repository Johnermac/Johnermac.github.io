// Copy-to-clipboard buttons + language tags for code blocks.
// Styles live in assets/css/main.scss (.window-container / .window-lang / .code-copy-btn).

(function () {
  var codeChunks = document.querySelectorAll("pre.highlight");
  if (!codeChunks.length || typeof ClipboardJS === "undefined") return;

  var COPY_ICON = "<i class='far fa-copy btn-icon' aria-hidden='true'></i>";
  var OK_ICON = "<i class='fas fa-check btn-icon' aria-hidden='true'></i>";
  var ERR_ICON = "<i class='far fa-times-circle btn-icon' aria-hidden='true'></i>";

  function languageOf(codeChunk) {
    var rouge = codeChunk.closest(".highlighter-rouge");
    if (!rouge) return "";
    var match = rouge.className.match(/language-([a-z0-9+#_-]+)/i);
    return match ? match[1] : "";
  }

  codeChunks.forEach(function (codeChunk) {
    var windowContainer = document.createElement("div");
    windowContainer.classList.add("window-container");

    var windowHeader = document.createElement("div");
    windowHeader.classList.add("window-header");

    var lang = document.createElement("span");
    lang.classList.add("window-lang");
    lang.textContent = languageOf(codeChunk);

    var btn = document.createElement("button");
    btn.setAttribute("type", "button");
    btn.setAttribute("aria-label", "Copy code");
    btn.setAttribute("title", "Copy code");
    btn.classList.add("code-copy-btn");
    btn.innerHTML = COPY_ICON;

    windowHeader.appendChild(lang);
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
      btn.innerHTML = COPY_ICON;
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
    flashState(e.trigger, "is--copied", OK_ICON);
  });

  clipboards.on("error", function (e) {
    flashState(e.trigger, "is--error", ERR_ICON);
  });
})();
