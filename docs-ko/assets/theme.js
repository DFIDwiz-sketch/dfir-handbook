// 디자인 보조 스크립트 (docs/assets 와 docs-ko/assets 에 같은 파일)

// 1) 색 모드 순서가 바뀌어서(라이트가 기본), 예전에 저장된 선택을 한 번만 지우고 라이트로 시작합니다.
//    이후에 직접 다크로 바꾸면 그 선택은 정상적으로 기억됩니다.
function dfirResetOldPalette() {
  try {
    var FLAG = "dfir-theme-v2";
    if (localStorage.getItem(FLAG)) return;
    Object.keys(localStorage).forEach(function (k) {
      if (/\.__palette$/.test(k)) localStorage.removeItem(k);
    });
    localStorage.setItem(FLAG, "1");
    var light = document.querySelector('input[name="__palette"][data-md-color-scheme="default"]');
    if (light && document.body.getAttribute("data-md-color-scheme") !== "default") {
      light.checked = true;
      light.dispatchEvent(new Event("change", { bubbles: true }));
    }
  } catch (e) { /* 저장소를 쓸 수 없는 브라우저 — 그냥 넘어감 */ }
}

// 2) 홈의 큰 검색창(라벨): 누르면 검색이 열리고 바로 입력할 수 있게 + 키보드 Enter / Space 지원
document.addEventListener("click", function (e) {
  if (!(e.target.closest && e.target.closest(".dfir-search"))) return;
  setTimeout(function () {
    var input = document.querySelector(".md-search__input");
    if (input) input.focus();
  }, 50);
});
document.addEventListener("keydown", function (e) {
  var box = e.target.closest && e.target.closest(".dfir-search");
  if (box && (e.key === "Enter" || e.key === " ")) {
    e.preventDefault();
    box.click();
  }
});

if (window.document$) {
  document$.subscribe(dfirResetOldPalette);
} else {
  document.addEventListener("DOMContentLoaded", dfirResetOldPalette);
}

// Post-Exploitation is a collapsible chapter; its overview stays in the submenu.
function dfirPreparePostExNav() {
  var links = document.querySelectorAll('.md-nav--primary a.md-nav__link[href]:not([data-dfir-postex-overview])');
  Array.prototype.forEach.call(links, function (link) {
    var url;
    try { url = new URL(link.href, location.href); } catch (e) { return; }
    if (!/\/redteam\/post-exploitation\/$/.test(url.pathname)) return;

    var item = link.closest('li.md-nav__item--nested');
    if (!item || item.dataset.dfirPostexReady) return;
    var toggle = item.querySelector(':scope > input.md-nav__toggle');
    var panel = item.querySelector(':scope > nav.md-nav');
    var list = panel && panel.querySelector(':scope > ul.md-nav__list');
    if (!toggle || !panel || !list) return;
    item.dataset.dfirPostexReady = 'true';
    item.classList.remove('md-nav__item--section');

    var overviewItem = document.createElement('li');
    overviewItem.className = 'md-nav__item';
    var overviewLink = document.createElement('a');
    overviewLink.href = link.href;
    overviewLink.className = 'md-nav__link';
    overviewLink.dataset.dfirPostexOverview = 'true';
    overviewLink.textContent = document.documentElement.lang === 'ko' ? '개요' : 'Overview';
    if (location.pathname === url.pathname) {
      overviewLink.classList.add('md-nav__link--active');
      overviewLink.setAttribute('aria-current', 'page');
    }
    overviewItem.appendChild(overviewLink);
    list.insertBefore(overviewItem, list.firstChild);

    var button = document.createElement('button');
    button.type = 'button';
    button.className = link.className + ' dfir-nav-toggle';
    while (link.firstChild) button.appendChild(link.firstChild);
    panel.id = toggle.id + '_panel';
    button.setAttribute('aria-controls', panel.id);
    link.replaceWith(button);

    var key = 'dfir-post-exploitation-expanded';
    var expanded = false;
    try { expanded = sessionStorage.getItem(key) === 'true'; } catch (e) {}
    toggle.checked = expanded;

    function syncExpansion() {
      var state = toggle.checked ? 'true' : 'false';
      button.setAttribute('aria-expanded', state);
      panel.setAttribute('aria-expanded', state);
      try { sessionStorage.setItem(key, state); } catch (e) {}
    }
    toggle.addEventListener('change', syncExpansion);
    button.addEventListener('click', function () {
      toggle.checked = !toggle.checked;
      toggle.dispatchEvent(new Event('change', { bubbles: true }));
    });
    syncExpansion();
  });
}
if (window.document$) {
  document$.subscribe(dfirPreparePostExNav);
} else if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', dfirPreparePostExNav);
} else {
  dfirPreparePostExNav();
}
