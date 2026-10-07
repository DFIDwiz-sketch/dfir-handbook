// 언어 선택 버튼을 누르면 "같은 페이지"의 다른 언어 버전으로 이동합니다.
// (기본 동작은 각 언어의 홈으로 가기 때문에 이 스크립트가 경로를 바꿔 줍니다.)
document.addEventListener("click", function (e) {
  var a = e.target.closest && e.target.closest("a[hreflang]");
  if (!a) return;
  var roots = Array.prototype.map.call(
    document.querySelectorAll("a[hreflang]"),
    function (x) { return new URL(x.href, location.href).pathname; }
  ).sort(function (x, y) { return y.length - x.length; });   // 긴 경로(/ko/) 먼저
  var here = location.pathname;
  var current = roots.find(function (r) { return here.indexOf(r) === 0; });
  if (!current) return;                                       // 모르면 기본 동작
  var rest = here.slice(current.length);
  var target = new URL(a.href, location.href).pathname + rest + location.hash;
  e.preventDefault();
  e.stopPropagation();
  location.href = target;
}, true);
