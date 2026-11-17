"use strict";
/* Проверки интерфейса выхода IKEv2: настоящий код панели (app/static/js) без браузера и сети.
   Запуск: node --test tests/ikev2_ui.test.js */
const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const STATIC = path.join(__dirname, "../app/static");

/** Части панели в порядке тегов <script> в index.html, кроме start.js: он запускает загрузку состояния. */
function panelFiles() {
  const html = fs.readFileSync(path.join(STATIC, "index.html"), "utf8");
  return [...html.matchAll(/<script src="static\/(js\/[\w-]+\.js)"/g)]
    .map((m) => path.join(STATIC, m[1])).filter((p) => !p.endsWith("start.js"));
}

/** Подмены браузерных границ (DOM, сеть, окна) оставляют выбор типа, отрисовку и сборку запроса настоящими.
    t возвращает ключ текста: проверки не зависят от перевода. */
function panel() {
  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      value: "", checked: false, hidden: false, disabled: false,
      addEventListener: mock.fn(), setAttribute: mock.fn(),
      classList: { toggle: mock.fn() },
    });
    return elements.get(selector);
  };
  const buttons = ["awg", "socks5", "ikev2"].map((kind) => ({
    dataset: { v: kind }, setAttribute: mock.fn(), disabled: false,
  }));
  const context = vm.createContext({
    document: {
      querySelector: mock.fn(element),
      querySelectorAll: mock.fn((selector) => selector === "#u-kind button" ? buttons : []),
      addEventListener: mock.fn(),
    },
    location: { hash: "#exits" }, window: { addEventListener: mock.fn() },
    localStorage: { getItem: () => null, setItem: () => {} },
    matchMedia: () => ({ matches: false, addEventListener: mock.fn() }),
    fetch: mock.fn(() => new Promise(() => {})),
    t: (key) => key, th: (key) => key, fmtNum: String, LANG: "en", LANGS: { en: { name: "English" } },
    captureModal: mock.fn(), captureApi: mock.fn(async () => ({ id: "u_test" })), finish: mock.fn(),
  });
  for (const file of panelFiles()) vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  vm.runInContext(`S = {upstreams: [], lists: [], routing: {rules: [], default: "direct"}};
    openModal = captureModal; api = captureApi; closeModal = finish; toast = finish; refresh = finish;`, context);
  return { context, element, buttons };
}

/* Новый выход IKEv2 при основном пути «Напрямую»: форма собирает JSON-конфиг, а сам выход не становится
   основным — галочку основного выхода новый выход AWG получает сам, IKEv2 нет (корпоративный VPN не для всего
   трафика). Ошибки разбора приходят с field="config", поэтому поля IKEv2 помечены этим полем. */
test("Новый выход IKEv2: реквизиты в JSON-конфиге, основным выходом он не становится", async () => {
  const { context, element, buttons } = panel();
  await vm.runInContext("editUpstream(null)", context);
  const html = context.captureModal.mock.calls[0].arguments[1];
  assert.match(html, /data-v="ikev2"/);
  for (const id of ["u-ih", "u-ir", "u-il", "u-iu", "u-iw", "u-ic", "u-im"]) {
    const tag = html.match(new RegExp(`<(input|textarea)[^>]*id="${id}"[^>]*>`));
    assert.ok(tag, id);
    assert.match(tag[0], /data-field="config"/, id);
  }
  assert.equal(element("#u-rdef").checked, true);          // новый выход AWG — основной, как в upstream
  buttons[2].onclick();
  assert.equal(element("#u-ike").hidden, false);
  assert.equal(element("#u-sf").hidden, true);
  assert.equal(element("#u-configf").hidden, true);
  assert.equal(element("#u-filef").hidden, true);
  assert.equal(element("#u-route").hidden, false);
  assert.equal(element("#u-rdef").checked, false);
  assert.equal(element("#u-fb").value, "block");
  element("#u-name").value = "Company";
  element("#u-ih").value = "vpn.example.com";
  element("#u-ir").value = "vpn.example.com";
  element("#u-iu").value = "employee";
  element("#u-iw").value = ' p\\a"ss ';
  element("#u-im").value = "1300";
  element("#u-doms").value = "portal.example.com";
  await element("#u-save").onclick();
  const [method, resource, body] = context.captureApi.mock.calls[0].arguments;
  assert.equal(method, "POST");
  assert.equal(resource, "upstreams");
  const conf = JSON.parse(body.config);
  assert.equal(conf.kind, "ikev2");
  assert.equal(conf.password, ' p\\a"ss ');
  assert.equal(conf.host, "vpn.example.com");
  assert.equal(conf.mtu, 1300);
  assert.equal(body.routing.domains, "portal.example.com");
  assert.equal(body.routing.default, false);
  assert.equal(body.fallback, "block");
  assert.equal("quic" in body, false);
});

/* Правка выхода: сохранённые реквизиты в форме, тип менять нельзя. */
test("Правка выхода IKEv2 показывает сохранённые реквизиты", async () => {
  const { context, element, buttons } = panel();
  vm.runInContext(`S.upstreams = [{id: "ike", name: "Company", num: 1, kind: "ikev2", fallback: "block",
    enabled: true, refs: [], traffic: {}, health: {}}];`, context);
  context.captureApi.mock.mockImplementation(async () => ({ config: JSON.stringify({
    kind: "ikev2", host: "vpn.example.com", remote_id: "id.example.com", local_id: "", user: "employee",
    password: "secret", ca: "", mtu: 1280 }) }));
  await vm.runInContext('editUpstream("ike")', context);
  const html = context.captureModal.mock.calls[0].arguments[1];
  assert.match(html, /id="u-ih"[^>]*value="vpn\.example\.com"/);
  assert.match(html, /id="u-ir"[^>]*value="id\.example\.com"/);
  assert.equal(element("#u-ike").hidden, false);
  assert.deepEqual(buttons.map((b) => b.disabled), [true, true, false]);
});

/* Причина отказа видна, пока панель ещё повторяет попытки, а не только после их остановки. */
test("Карточка IKEv2: тип, установленная сессия и причина отказа", () => {
  const { context } = panel();
  const html = (health) => vm.runInContext(`S.upstreams = [{id: "ike", name: "Company", num: 1, kind: "ikev2",
    enabled: true, refs: [], traffic: {}, fallback: "block", health: ${JSON.stringify(health)}}];
    viewExits();`, context);
  const failed = html({ state: "stale", healthy: false, error: { $t: "ike.untrusted_server", p: {} } });
  assert.match(failed, /ike\.untrusted_server/);
  assert.match(failed, /<span class="tag">IKEv2<\/span>/);
  assert.match(html({ state: "up", healthy: true }), /ike\.connected/);
});

/* У IKEv2 нет рукопожатия AWG: строка выхода в обзоре говорит об установленной сессии, а не о «рукопожатии». */
test("Обзор: рабочий выход IKEv2 показывает установленную сессию", () => {
  const { context } = panel();
  const html = vm.runInContext(`S = {...S, clients: [], events: [], global_effective: "direct",
    upstreams: [{id: "ike", name: "Company", num: 1, kind: "ikev2", enabled: true, refs: [], traffic: {},
      fallback: "block", endpoint: "vpn.example.com:500", health: {state: "up", healthy: true}}]};
    viewOverview();`, context);
  assert.match(html, /ike\.connected/);
  assert.doesNotMatch(html, /ov\.handshake/);
});
