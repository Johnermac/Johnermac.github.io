// Floating search overlay — close on Escape or backdrop click.
(function () {
  function closeIfOpen() {
    var open = document.querySelector(".search-content.is--visible");
    if (!open) return;
    var toggle = document.querySelector(".search__toggle");
    if (toggle) toggle.click();
  }

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeIfOpen();
  });

  document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("search-content")) {
      closeIfOpen();
    }
  });
})();
