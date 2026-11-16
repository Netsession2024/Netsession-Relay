// Netsession Relay UI: progressive enhancement only. Every form also works without JavaScript.
// Parts: confirmation dialog, switches, games search/filter, live updates (server-sent events).
(function () {
  "use strict";
  var doc = document, body = doc.body;
  var csrf = body.dataset.csrf || "";
  function $(id) { return doc.getElementById(id); }
  function all(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }
  function num(n) { return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, " "); }
  function setText(el, text) { if (el && el.textContent !== text) el.textContent = text; }
  function announce(text) { var a = $("announce"); if (a) { a.textContent = ""; setTimeout(function () { a.textContent = text; }, 50); } }

  // ---- times: the server writes UTC, show the browser's local time ----
  function two(n) { return (n < 10 ? "0" : "") + n; }
  function fmtTime(d, kind) {
    var t = two(d.getHours()) + ":" + two(d.getMinutes());
    if (kind === "time") return t + ":" + two(d.getSeconds());
    return two(d.getDate()) + "." + two(d.getMonth() + 1) + ". " + t;
  }
  function localTimes(root) {
    all("time[datetime]", root).forEach(function (el) {
      var d = new Date(el.getAttribute("datetime"));
      if (!isNaN(d)) el.textContent = fmtTime(d, el.dataset.fmt);
    });
  }
  localTimes(doc);

  // ---- toast ----
  var toastTimer;
  function toast(text, kind) {
    var t = $("toast");
    if (!t) return;
    $("toast-text").textContent = text;
    t.className = "toast" + (kind ? " toast-" + kind : "");
    var use = t.querySelector("#toast-icon use");
    if (use) use.setAttribute("href", "/static/icons.svg#i-" + (kind ? "alert" : "check"));
    t.hidden = false;
    clearTimeout(toastTimer);
    // errors stay until closed, confirmations leave by themselves
    if (kind !== "danger") toastTimer = setTimeout(function () { t.hidden = true; }, kind === "warn" ? 9000 : 5000);
  }
  if ($("toast-close")) $("toast-close").addEventListener("click", function () { $("toast").hidden = true; });

  // ---- confirmation dialog (native <dialog>: focus stays inside, Esc closes) ----
  var dlg = $("confirm");
  function confirmBox(d, onOK) {
    if (!dlg || !dlg.showModal) { if (window.confirm(d.confirm)) onOK(); return; }
    $("confirm-title").textContent = d.confirmTitle || "Sicher?";
    $("confirm-text").textContent = d.confirm || "";
    $("confirm-ok").textContent = d.confirmOk || "Ja, weiter";
    dlg.returnValue = "cancel";
    dlg.onclose = function () { if (dlg.returnValue === "ok") onOK(); };
    dlg.showModal();
    $("confirm-cancel").focus();
  }
  var stopLink = $("stop-link"), stopForm = $("stop-form");
  if (stopLink && stopForm) {
    stopLink.addEventListener("click", function (e) {
      e.preventDefault();
      confirmBox(stopForm.dataset, function () { stopForm.submit(); });
    });
  }
  all("form[data-confirm]").forEach(function (f) {
    if (f === stopForm || f.classList.contains("toggle-form")) return;
    f.addEventListener("submit", function (e) {
      if (f.dataset.confirmed) return;
      e.preventDefault();
      confirmBox(f.dataset, function () { f.dataset.confirmed = "1"; f.submit(); });
    });
  });

  // account menu: close on outside click and Esc
  var account = doc.querySelector("details.account");
  if (account) {
    doc.addEventListener("click", function (e) { if (account.open && !account.contains(e.target)) account.open = false; });
    doc.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && account.open) { account.open = false; account.querySelector("summary").focus(); }
    });
  }

  // ---- switches: apply without reloading the page ----
  function setSwitch(f, on) {
    var btn = f.querySelector(".switch");
    btn.setAttribute("aria-checked", on ? "true" : "false");
    setText(btn.querySelector(".switch-word"), on ? "An" : "Aus");
    f.querySelector('input[name="on"]').value = on ? "0" : "1";
    var row = f.closest("[data-on]");
    if (row) row.dataset.on = on ? "1" : "0";
  }
  function send(f) {
    var btn = f.querySelector(".switch");
    btn.classList.add("busy");
    btn.setAttribute("aria-busy", "true");
    fetch(f.action, {
      method: "POST",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf },
      body: new FormData(f),
      credentials: "same-origin"
    }).then(function (r) { return r.json(); }).then(function (a) {
      if (a.error) { toast(a.error, "danger"); return; }
      setSwitch(f, a.enabled);
      var msg = a.message || "Angewendet.";
      if (a.warnings && a.warnings.length) toast(msg + " Hinweis: " + a.warnings.join(" · "), "warn");
      else toast(msg);
      doc.dispatchEvent(new Event("relay:changed"));
    }).catch(function () {
      toast("Keine Antwort vom Relay-Server. Der Schalter wurde nicht geändert.", "danger");
    }).then(function () {
      btn.classList.remove("busy");
      btn.removeAttribute("aria-busy");
    });
  }
  all("form.toggle-form").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var turningOff = f.querySelector('input[name="on"]').value === "0";
      if (f.dataset.confirm && turningOff) confirmBox(f.dataset, function () { send(f); });
      else send(f);
    });
  });

  // ---- pages with a server-rendered fragment that refreshes every 5 s (players, port finder) ----
  // The swap must not disturb someone reading: opened <details data-key> stay open, keyboard focus stays
  // on the same link or summary, and nothing is replaced while text inside is selected (copying bytes).
  function focusMark(box) {
    var a = doc.activeElement;
    if (!a || !box.contains(a)) return null;
    if (a.tagName === "SUMMARY" && a.parentNode.dataset.key) return { key: a.parentNode.dataset.key };
    if (a.getAttribute("href")) return { href: a.getAttribute("href") };
    return null;
  }
  all("[data-refresh]").forEach(function (box) {
    var last = null;
    setInterval(function () {
      if (doc.hidden) return;
      fetch(box.dataset.refresh, { credentials: "same-origin" }).then(function (r) { return r.ok ? r.text() : null; }).then(function (html) {
        if (html === null || html === last) return;
        var sel = window.getSelection && window.getSelection();
        if (sel && !sel.isCollapsed && sel.anchorNode && box.contains(sel.anchorNode)) return;
        var open = all("details[open][data-key]", box).map(function (d) { return d.dataset.key; });
        var mark = focusMark(box);
        last = html;
        box.innerHTML = html;
        localTimes(box);
        all("details[data-key]", box).forEach(function (d) {
          if (open.indexOf(d.dataset.key) >= 0) d.open = true;
          if (mark && mark.key === d.dataset.key) d.querySelector("summary").focus();
        });
        if (mark && mark.href) all("a[href]", box).some(function (a) {
          if (a.getAttribute("href") !== mark.href) return false;
          a.focus();
          return true;
        });
      }).catch(function () {});
    }, 5000);
  });

  // ---- copy button (monitoring token); hidden without JavaScript, the text is selectable anyway ----
  all("[data-copy]").forEach(function (btn) {
    var src = $(btn.dataset.copy);
    if (!src) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var mark = function () {
        var r = doc.createRange();
        r.selectNodeContents(src);
        var s = window.getSelection();
        s.removeAllRanges();
        s.addRange(r);
        toast("Markiert. Jetzt mit Strg+C kopieren.", "warn");
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(src.textContent).then(function () { toast(btn.dataset.copyDone || "Kopiert."); }, mark);
      } else mark();
    });
  });

  // ---- a select that shows a field only for one value (multicast group); the hidden field is not sent ----
  all("select[data-toggles]").forEach(function (sel) {
    var field = $(sel.dataset.toggles);
    if (!field) return;
    var sync = function () {
      var on = sel.value === sel.dataset.togglesOn;
      field.hidden = !on;
      all("input", field).forEach(function (i) { i.disabled = !on; });
    };
    sel.addEventListener("change", sync);
    sync();
  });

  // ---- games: search + filter ----
  var games = $("games"), applyFilter = function () {};
  if (games) {
    var search = $("game-search"), empty = $("game-empty"), nolan = $("nolan");
    var rows = all(".grow", games);
    var filter = "all";
    applyFilter = function (quiet) {
      var q = (search.value || "").trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var d = row.dataset;
        var ok = !q || d.search.toLowerCase().indexOf(q) >= 0;
        if (ok && filter !== "all" && d.nolan) ok = false;
        if (ok && filter === "an") ok = d.on === "1";
        if (ok && filter === "aus") ok = d.on === "0";
        if (ok && filter === "unsicher") ok = d.unsure === "1";
        row.hidden = !ok;
        if (ok) shown++;
      });
      all("[data-gsec]", games).forEach(function (sec) { sec.hidden = !sec.querySelector(".grow:not([hidden])"); });
      if (nolan && q && !nolan.hidden) nolan.open = true;
      empty.hidden = shown > 0;
      if (!quiet) setText($("game-count"), shown === 1 ? "1 Spiel gefunden" : shown + " Spiele gefunden");
    };
    var setFilter = function (name) {
      filter = name;
      all(".chip[data-filter]").forEach(function (o) { o.setAttribute("aria-pressed", o.dataset.filter === name ? "true" : "false"); });
      applyFilter();
    };
    search.addEventListener("input", function () { applyFilter(); });
    all(".chip[data-filter]").forEach(function (c) { c.addEventListener("click", function () { setFilter(c.dataset.filter); }); });
    doc.addEventListener("keydown", function (e) {
      if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(doc.activeElement.tagName) && !(dlg && dlg.open)) { e.preventDefault(); search.focus(); search.select(); }
      if (e.key === "Escape" && doc.activeElement === search && search.value) { search.value = ""; applyFilter(); }
    });
    var params = new URLSearchParams(location.search);
    if (params.get("q")) search.value = params.get("q");
    var want = params.get("filter");
    if (want && doc.querySelector('.chip[data-filter="' + want.replace(/[^a-z]/g, "") + '"]')) setFilter(want);
    else if (search.value) applyFilter();
    doc.addEventListener("relay:changed", function () { countGames(); if (filter !== "all") applyFilter(true); });
  }
  function countGames() {
    if (!games) return;
    var on = all('.grow[data-on="1"]', games).length, off = all('.grow[data-on="0"]', games).length;
    setText($("n-on"), String(on));
    setText($("n-off"), String(off));
    all('[data-live="games_on"]').forEach(function (el) { setText(el, String(on)); });
  }

  // ---- live updates ----
  var liveURL = body.dataset.liveUrl;
  if (!liveURL || !window.EventSource) return;
  var liveEl = $("live"), liveText = $("live-text"), conn = $("conn");
  var es = null, lastAt = Date.now(), lastData = null, prev = {}, seenAlarms = null, lastState = null, lost = false;

  function get(o, path) {
    return path.split(".").reduce(function (x, k) { return x == null ? x : x[k]; }, o);
  }
  function icon(name) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = doc.createElementNS(ns, "svg"), use = doc.createElementNS(ns, "use");
    svg.setAttribute("class", "ic");
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "/static/icons.svg#i-" + name);
    svg.appendChild(use);
    return svg;
  }
  function el(tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  // re-render a table body from a list when it changed; columns: "field:classes,…"
  function rowsOf(tbody, list) {
    var key = JSON.stringify(list);
    if (prev[tbody.dataset.rows] === key) return;
    prev[tbody.dataset.rows] = key;
    var cols = tbody.dataset.cols.split(",").map(function (c) { var p = c.split(":"); return { f: p[0], cls: p[1] || "" }; });
    var frag = doc.createDocumentFragment();
    list.forEach(function (item) {
      var tr = el("tr");
      cols.forEach(function (c) {
        var v = item[c.f];
        tr.appendChild(el("td", c.cls, /\bnum\b/.test(c.cls) ? num(v) : String(v)));
      });
      frag.appendChild(tr);
    });
    if (!list.length) {
      var td = el("td", "muted", tbody.dataset.empty || "–");
      td.colSpan = cols.length;
      frag.appendChild(el("tr")).appendChild(td);
    }
    tbody.replaceChildren(frag);
  }
  function alarms(list) {
    var ul = $("alarms");
    var kinds = list.map(function (a) { return a.kind; });
    if (seenAlarms) {
      var fresh = list.filter(function (a) { return seenAlarms.indexOf(a.kind) < 0; });
      if (fresh.length) announce("Neuer Alarm: " + fresh.map(function (a) { return a.title; }).join(", "));
      else if (seenAlarms.length && !kinds.length) announce("Alarme beendet.");
    }
    seenAlarms = kinds;
    var st = $("stat-alarm");
    if (st) {
      st.classList.toggle("stat-alarm", list.length > 0);
      setText($("stat-alarm-sub"), list.length ? "siehe unten" : "alles ruhig");
    }
    if (!ul) return;
    var key = JSON.stringify(list);
    if (prev.alarms === key) return;
    prev.alarms = key;
    var frag = doc.createDocumentFragment();
    list.forEach(function (a) {
      var li = el("li", "alarm"), box = el("div"), title = el("p", "alarm-title");
      li.appendChild(icon("alert"));
      title.appendChild(el("b", "", a.title));
      title.appendChild(doc.createTextNode(" "));
      title.appendChild(el("span", "alarm-meta", num(a.count) + "× · zuletzt " + fmtTime(new Date(a.last), "time")));
      box.appendChild(title);
      if (a.hint) box.appendChild(el("p", "", a.hint));
      box.appendChild(el("p", "small muted")).appendChild(el("span", "mono", a.where));
      box.appendChild(el("p", "small muted", a.detail));
      if (ul.hasAttribute("data-can-ack")) box.appendChild(ackForm(a.kind));
      li.appendChild(box);
      frag.appendChild(li);
    });
    ul.replaceChildren(frag);
    ul.hidden = !list.length;
    $("alarms-empty").hidden = list.length > 0;
  }
  function ackForm(kind) {
    var f = el("form", "ack-form");
    f.method = "post";
    f.action = "/alarme/" + encodeURIComponent(kind) + "/gesehen";
    var c = el("input"); c.type = "hidden"; c.name = "csrf"; c.value = csrf; f.appendChild(c);
    var b = el("button", "btn-outline btn-sm"); b.type = "submit";
    b.appendChild(icon("check")); b.appendChild(el("span", "", "Gesehen"));
    f.appendChild(b);
    return f;
  }
  function seen(list) {
    var box = $("seen-box"), ul = $("alarms-seen");
    if (!box || !ul) return;
    list = list || [];
    var key = JSON.stringify(list);
    if (prev.seen === key) return;
    prev.seen = key;
    box.hidden = !list.length;
    setText($("seen-count"), String(list.length));
    var frag = doc.createDocumentFragment();
    list.forEach(function (a) {
      var li = el("li", "alarm alarm-seen"), box2 = el("div"), title = el("p", "alarm-title");
      li.appendChild(icon("check"));
      title.appendChild(el("b", "", a.title));
      title.appendChild(doc.createTextNode(" "));
      title.appendChild(el("span", "alarm-meta", num(a.count) + "× · zuletzt " + fmtTime(new Date(a.last), "time") + (a.acked_by ? " · gesehen von " + a.acked_by : "")));
      box2.appendChild(title);
      box2.appendChild(el("p", "small muted")).appendChild(el("span", "mono", a.where));
      li.appendChild(box2);
      frag.appendChild(li);
    });
    ul.replaceChildren(frag);
  }

  function apply(v) {
    // plain values: text of every [data-live="path"]
    all("[data-live]").forEach(function (e) {
      if (e.dataset.live === "games_on" && games) return; // counted from the rows
      var val = get(v, e.dataset.live);
      if (val == null) return;
      setText(e, typeof val === "number" ? num(val) : String(val));
    });
    // operating state: tone, icon, what is offered
    all("[data-tone-live]").forEach(function (e) { e.dataset.tone = v.state.tone; });
    all("[data-icon-live] use").forEach(function (u) {
      var href = "/static/icons.svg#i-" + v.state.icon;
      if (u.getAttribute("href") !== href) u.setAttribute("href", href);
    });
    all("[data-when]").forEach(function (e) { e.hidden = e.dataset.when.split(" ").indexOf(v.state.key) < 0; });
    if (stopLink) stopLink.hidden = !v.state.can_stop;
    if ($("needs-apply")) $("needs-apply").hidden = !v.needs_apply;
    if (lastState && lastState !== v.state.key) announce("Betriebsart jetzt: " + v.state.label + ". " + v.state.headline + ".");
    lastState = v.state.key;

    // VLAN tiles and rows
    var max = 10;
    v.vlans.forEach(function (x) { if (x.in_per_s > max) max = x.in_per_s; });
    v.vlans.forEach(function (x) {
      all('[data-vlan="' + x.vid + '"]').forEach(function (t) {
        if (t.dataset.status !== x.status) t.dataset.status = x.status;
        setText(t.querySelector('[data-f="rate"]'), num(x.in_per_s));
        setText(t.querySelector('[data-f="status"]'), x.status);
        setText(t.querySelector('[data-f="in"]'), num(x.in));
        setText(t.querySelector('[data-f="out"]'), num(x.out));
        var bar = t.querySelector(".vbar i");
        if (bar) bar.style.width = Math.round(100 * x.in_per_s / max) + "%";
      });
    });

    // rule counters (game page) and per-game counters (games list)
    var rule = {};
    v.rules.forEach(function (r) { rule[r.id] = r; });
    all("[data-rule]").forEach(function (tr) {
      var r = rule[tr.dataset.rule] || { rx: 0, relayed: 0 };
      setText(tr.querySelector('[data-f="rx"]'), num(r.rx));
      setText(tr.querySelector('[data-f="relayed"]'), num(r.relayed));
    });
    if (games) {
      var enabled = {};
      v.enabled.forEach(function (id) { enabled[id] = true; });
      var changed = false;
      all(".grow[data-rules]", games).forEach(function (row) {
        var sum = 0;
        row.dataset.rules.split(" ").forEach(function (id) { if (rule[id]) sum += rule[id].rx; });
        var before = prev["g:" + row.dataset.id];
        row.classList.toggle("hot", before !== undefined && sum > before);
        prev["g:" + row.dataset.id] = sum;
        setText(row.querySelector('[data-f="rx"]'), num(sum));
        // someone else switched a game: follow, unless this switch is just being used
        var on = !!enabled[row.dataset.id], f = row.querySelector("form.toggle-form");
        if ((row.dataset.on === "1") !== on && !(f && f.querySelector(".busy"))) {
          if (f) setSwitch(f, on); else { row.dataset.on = on ? "1" : "0"; setText(row.querySelector("[data-onoff]"), on ? "An" : "Aus"); }
          changed = true;
        }
      });
      if (changed) doc.dispatchEvent(new Event("relay:changed"));
    }
    var single = doc.querySelector("[data-game-switch]");
    if (single) {
      var isOn = v.enabled.indexOf(single.dataset.id) >= 0, sf = single.querySelector("form.toggle-form");
      if (sf && !sf.querySelector(".busy") && (sf.querySelector(".switch").getAttribute("aria-checked") === "true") !== isOn) setSwitch(sf, isOn);
      if (!sf) setText(single.querySelector("[data-onoff]"), isOn ? "An" : "Aus");
    }

    alarms(v.alarms);
    seen(v.seen);
    all("tbody[data-rows]").forEach(function (tb) { rowsOf(tb, v[tb.dataset.rows] || []); });

    // diagnosis: fetch the server-rendered fragment again when something relevant flipped
    var diag = $("diagnose");
    if (diag) {
      var rx = 0, tx = 0;
      diag.dataset.rules.split(" ").forEach(function (id) { if (rule[id]) { rx += rule[id].rx; tx += rule[id].relayed; } });
      var sig = [v.state.key, v.enabled.indexOf(diag.dataset.id) >= 0, rx > 0, tx > 0, v.hash].join("|");
      if (prev.diag !== undefined && prev.diag !== sig) {
        fetch(diag.dataset.fragment, { credentials: "same-origin" }).then(function (r) { return r.ok ? r.text() : null; }).then(function (html) {
          if (html) diag.innerHTML = html; // same-origin, rendered and escaped by the server template
        }).catch(function () {});
      }
      prev.diag = sig;
    }
  }

  function setLive(state) {
    if (!liveEl) return;
    liveEl.dataset.state = state;
    liveEl.removeAttribute("title");
    setText(liveText, state === "on" ? "Live" : state === "off" ? "Getrennt" : "Verbindet");
  }
  function markLost(isLost) {
    if (lost === isLost) return;
    lost = isLost;
    body.classList.toggle("stale", lost);
    if (conn) {
      if (lost) setText($("conn-text"), "Keine Verbindung zum Relay-Server. Die Zahlen sind von " + (lastAt ? fmtTime(new Date(lastAt), "time") : "vorhin") + ". Neuer Versuch läuft.");
      conn.hidden = !lost;
    }
    setLive(lost ? "off" : "on");
  }
  function onStatus(e) {
    var v;
    try { v = JSON.parse(e.data); } catch (err) { return; }
    lastAt = Date.now();
    lastData = v;
    markLost(false);
    setLive("on");
    apply(v);
  }
  function connect() {
    if (es) es.close();
    es = new EventSource(liveURL);
    es.addEventListener("status", onStatus);
    es.addEventListener("bye", sessionGone);
    es.onerror = function () {
      // EventSource retries by itself while CONNECTING; CLOSED means the server refused (e.g. session ended)
      if (es.readyState === 2) checkSession();
    };
  }
  function sessionGone() {
    if (es) es.close();
    es = null;
    body.classList.add("stale");
    setLive("off");
    if (conn) {
      setText($("conn-text"), "Deine Sitzung ist abgelaufen. Melde dich neu an.");
      var a = conn.querySelector("a");
      a.textContent = "Anmelden";
      a.href = "/login";
      conn.hidden = false;
    }
    clearInterval(watch);
  }
  function checkSession() {
    fetch("/api/v1/status", { headers: { "Accept": "application/json" }, credentials: "same-origin" }).then(function (r) {
      if (r.status === 401) sessionGone(); else setTimeout(connect, 3000);
    }).catch(function () { setTimeout(connect, 3000); });
  }
  // watchdog: no sample for 7 s means the numbers are stale, whatever the socket says
  var watch = setInterval(function () {
    if (doc.hidden || !es) return;
    if (lastAt && Date.now() - lastAt > 7000) markLost(true);
    if (lastAt && Date.now() - lastAt > 20000 && es.readyState !== 0) connect();
  }, 1000);
  // a hidden tab gives its connection back (browsers allow six per server) and reconnects when shown
  doc.addEventListener("visibilitychange", function () {
    if (doc.hidden) { if (es) { es.close(); es = null; } }
    else if (!es) { setLive("wait"); lastAt = Date.now(); connect(); }
  });
  setLive("wait");
  connect();
})();
