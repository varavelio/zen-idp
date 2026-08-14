// Zen IdP browser behavior: theme preference dropdown, native modal
// dialogs, and clipboard copy buttons. This is the only client-side script;
// it loads synchronously in the document head so the theme applies before
// first paint, and it relies solely on data attributes and event delegation
// to keep the strict Content-Security-Policy intact (no inline scripts, no
// eval).
(function () {
  "use strict";

  var THEME_KEY = "zen-idp-theme";
  var THEMES = ["system", "light", "dark"];
  var root = document.documentElement;

  // currentTheme returns the persisted theme, defaulting to system.
  function currentTheme() {
    var theme = root.dataset.theme;
    return THEMES.indexOf(theme) !== -1 ? theme : "system";
  }

  // applyTheme persists the choice and reflects it on the root element.
  // System mode sets no data-theme attribute at all, so the color scheme
  // follows the operating system through the media query.
  function applyTheme(theme) {
    if (theme === "system") {
      delete root.dataset.theme;
    } else {
      root.dataset.theme = theme;
    }
    localStorage.setItem(THEME_KEY, theme);
    syncThemePickers();
  }

  // syncThemePickers reflects the current theme on every picker: the trigger
  // icon and the checked menu option.
  function syncThemePickers() {
    var theme = currentTheme();
    document.querySelectorAll("[data-theme-picker]").forEach(function (picker) {
      THEMES.forEach(function (option) {
        var icon = picker.querySelector("[data-theme-icon-" + option + "]");
        if (icon) icon.classList.toggle("hidden", option !== theme);
      });
      picker.querySelectorAll("[data-theme-option]").forEach(function (option) {
        var active = option.getAttribute("data-theme-option") === theme;
        option.classList.toggle("bg-base-200", active);
        option.setAttribute("aria-checked", String(active));
        var check = option.querySelector("[data-theme-check]");
        if (check) check.classList.toggle("hidden", !active);
      });
    });
  }

  // closeThemeMenus collapses every open picker menu.
  function closeThemeMenus() {
    document.querySelectorAll("[data-theme-menu]").forEach(function (menu) {
      menu.classList.add("hidden");
      var trigger = menu.parentElement.querySelector("[data-theme-toggle]");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  }

  // Bootstrap before first paint: the persisted choice wins, otherwise the
  // system theme is used, leaving the media query in charge.
  var stored = localStorage.getItem(THEME_KEY);
  if (THEMES.indexOf(stored) === -1) {
    stored = "system";
    localStorage.setItem(THEME_KEY, stored);
  }
  if (stored === "system") {
    delete root.dataset.theme;
  } else {
    root.dataset.theme = stored;
  }
  document.addEventListener("DOMContentLoaded", syncThemePickers);

  document.addEventListener("click", function (event) {
    var target = event.target;

    // The theme-picker trigger toggles its menu.
    var trigger = target.closest("[data-theme-toggle]");
    if (trigger) {
      var menu = trigger.parentElement.querySelector("[data-theme-menu]");
      if (!menu) return;
      var open = menu.classList.toggle("hidden") === false;
      trigger.setAttribute("aria-expanded", String(open));
      return;
    }

    // A theme option applies the choice and closes the menu.
    var option = target.closest("[data-theme-option]");
    if (option) {
      applyTheme(option.getAttribute("data-theme-option"));
      closeThemeMenus();
      return;
    }

    // Clicks elsewhere collapse open menus.
    if (!target.closest("[data-theme-picker]")) {
      closeThemeMenus();
    }
  });

  // Escape collapses open menus.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeThemeMenus();
  });

  // [data-dialog-open="id"] opens the named modal dialog.
  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-dialog-open]");
    if (!opener) return;
    var dialog = document.getElementById(opener.getAttribute("data-dialog-open"));
    if (dialog && typeof dialog.showModal === "function") {
      dialog.showModal();
    }
  });

  // [data-dialog-close] closes the enclosing dialog.
  document.addEventListener("click", function (event) {
    var closeButton = event.target.closest("[data-dialog-close]");
    if (!closeButton) return;
    var closeDialog = closeButton.closest("dialog");
    if (closeDialog) closeDialog.close();
  });

  // [data-copy="text"] copies its value and flashes a confirmation.
  document.addEventListener("click", function (event) {
    var copyButton = event.target.closest("[data-copy]");
    if (!copyButton || !navigator.clipboard) return;
    navigator.clipboard.writeText(copyButton.getAttribute("data-copy")).then(function () {
      var idle = copyButton.querySelector("[data-copy-idle]");
      var done = copyButton.querySelector("[data-copy-done]");
      var label = copyButton.querySelector("[data-copy-label]");
      if (idle) idle.classList.add("hidden");
      if (done) done.classList.remove("hidden");
      if (label) label.textContent = "Copied";
      setTimeout(function () {
        if (idle) idle.classList.remove("hidden");
        if (done) done.classList.add("hidden");
        if (label) label.textContent = "Copy";
      }, 2000);
    });
  });

  // A click on the dimmed backdrop closes the open dialog.
  document.addEventListener("click", function (event) {
    var dialog = event.target.closest("dialog[open]");
    if (dialog && event.target === dialog) {
      dialog.close();
    }
  });
})();
