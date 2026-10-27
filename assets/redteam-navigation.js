
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
dfirPreparePostExNav();
if (window.document$) {
  document$.subscribe(dfirPreparePostExNav);
} else if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', dfirPreparePostExNav);
} else {
  dfirPreparePostExNav();
}
