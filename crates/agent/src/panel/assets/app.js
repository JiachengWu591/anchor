'use strict';
// AI Anchor 面板。数据一律当文字放进页面（textContent），不拼 HTML：域名、错误文本都来自网络。

const KEY = 'anchor-panel-token';
const STATE_EVERY_MS = 2000;
const HIDDEN_EVERY_MS = 30000;
const HISTORY_EVERY_MS = 30000;

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}

let token = null;
let period = 'day';
let hist = null;
let lastState = '';
let lastHist = '';
let lockedBase = null;
let failures = 0;
let toastTimer = 0;
let histAt = 0;

function gate(text) {
  $('app').hidden = true;
  $('gate').hidden = false;
  $('gate-text').textContent = text;
  document.title = 'AI Anchor';
}

function ungate() {
  $('gate').hidden = true;
  $('app').hidden = false;
}

async function api(path, body) {
  const opt = { headers: { Authorization: 'Bearer ' + token }, cache: 'no-store' };
  if (body) {
    opt.method = 'POST';
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (r.status === 401) {
    sessionStorage.removeItem(KEY);
    token = null;
    const e = new Error('会话已失效');
    e.expired = true;
    throw e;
  }
  let j = null;
  try {
    j = await r.json();
  } catch (_) {
    j = null;
  }
  if (!r.ok) throw new Error((j && j.error) || '请求失败（' + r.status + '）');
  return j;
}

function zhDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const parts = [[Math.floor(s / 86400), '天'], [Math.floor((s % 86400) / 3600), '小时'], [Math.floor((s % 3600) / 60), '分'], [s % 60, '秒']];
  const v = parts.filter((p) => p[0] > 0).map((p) => p[0] + ' ' + p[1]);
  return v.length ? v.join(' ') : '0 秒';
}

// ---- 现在的状态 ----

function renderChannel(ch) {
  $('channel').dataset.state = ch.state;
  $('ch-title').textContent = ch.title;
  $('ch-detail').textContent = ch.detail;
  $('ch-detail').hidden = !ch.detail;
  $('ch-advice').textContent = ch.advice;
  $('ch-advice').hidden = !ch.advice;
  lockedBase = typeof ch.locked_ms === 'number' ? { ms: ch.locked_ms, at: performance.now() } : null;
  renderTimer();
  document.title = 'AI Anchor · ' + ch.title.replace('AI 通道', '');
}

function renderTimer() {
  const t = $('ch-timer');
  if (!lockedBase) {
    t.hidden = true;
    return;
  }
  t.hidden = false;
  t.textContent = zhDuration(lockedBase.ms + (performance.now() - lockedBase.at));
}

function renderPath(segs, culprit) {
  const list = $('path');
  list.replaceChildren();
  let after = false;
  for (const s of segs) {
    const li = el('li');
    li.dataset.state = s.state;
    if (after) li.classList.add('after');
    li.append(el('span', 'dot'));
    const name = el('span', 'name', s.name);
    if (s.sub) name.append(el('span', 'sub', s.sub));
    if (culprit && s.id === culprit) {
      li.classList.add('culprit');
      name.append(el('span', 'tag', '卡在这里'));
      after = true;
    }
    li.append(name, el('span', 'text', s.text));
    list.append(li);
  }
}

function renderFacts(facts) {
  const dl = $('facts');
  dl.replaceChildren();
  for (const f of facts) dl.append(el('dt', '', f.k), el('dd', '', f.v));
}

function renderState(st) {
  const key = JSON.stringify([st.channel, st.path, st.culprit, st.facts]);
  if (key === lastState) return;
  lastState = key;
  renderChannel(st.channel);
  renderPath(st.path, st.culprit);
  renderFacts(st.facts);
}

// ---- 统计 ----

function stat(num, unit, cap, cls) {
  const box = el('div', 'stat' + (cls ? ' ' + cls : ''));
  const n = el('div', 'num', num);
  if (unit) n.append(el('small', '', unit));
  box.append(n, el('div', 'cap', cap));
  return box;
}

function renderSummary(s) {
  const stats = $('stats');
  stats.replaceChildren(
    stat(s.disconnects, '次', s.disconnects ? '断联（合并了 ' + s.errors + ' 条连接错误）' : '断联'),
    stat(s.locks, '次', s.locks ? 'AI 通道锁住，共 ' + s.locked : 'AI 通道锁住'),
    s.disconnects
      ? stat(s.unknown_pct, '%', '原因不明，目标低于 ' + s.unknown_target + '%', s.unknown_ok ? 'good' : 'bad')
      : stat('—', '', '原因不明的占比')
  );

  const causes = $('causes');
  causes.replaceChildren();
  if (s.causes.length) {
    const bar = el('div', 'bar');
    const legend = el('div', 'legend');
    for (const c of s.causes) {
      const part = el('span', 'c-' + c.id);
      part.style.flexGrow = String(c.n);
      part.title = c.label + ' ' + c.n + ' 次';
      bar.append(part);
      const item = el('span');
      item.append(el('i', 'c-' + c.id), document.createTextNode(c.label + ' '), el('b', '', c.n), document.createTextNode('（' + c.pct + '%）'));
      legend.append(item);
    }
    causes.append(bar, legend);
  }

  const bits = ['出口 IP 变化 ' + s.exit_ip_changes + ' 次', '内核意外退出 ' + s.kernel_restarts + ' 次', '网络变化 ' + s.net_changes + ' 次'];
  if (s.line_switches) bits.push('换线 ' + s.line_switches + ' 次');
  for (const p of s.probes) bits.push(p.label + ' ' + p.pct + '%');
  $('more').textContent = bits.join(' · ');
}

function renderHours(hours) {
  const box = $('hours');
  const axis = $('hours-axis');
  box.replaceChildren();
  axis.replaceChildren();
  hours.forEach((h, i) => {
    const bar = el('span');
    if (h.locked_s > 0) {
      bar.style.height = Math.max(8, Math.round((Math.min(h.locked_s, 3600) / 3600) * 100)) + '%';
    } else {
      bar.className = 'none';
    }
    bar.title = h.label + ' 点：锁住 ' + zhDuration(h.locked_s * 1000) + '，断联 ' + h.disconnects + ' 次';
    box.append(bar);
    if (i % 6 === 0 || i === hours.length - 1) axis.append(el('span', '', h.label + ' 点'));
  });
}

// 按钟点：每个钟点一根，满高表示看到的每一天都锁住过
function renderByHour(b) {
  const box = $('byhour');
  const axis = $('byhour-axis');
  box.replaceChildren();
  axis.replaceChildren();
  b.hours.forEach((h, i) => {
    const bar = el('span');
    if (h.days === 0) {
      bar.className = 'unseen';
    } else if (h.days_locked > 0) {
      bar.style.height = Math.max(10, Math.round(h.share * 100)) + '%';
    } else {
      bar.className = 'none';
    }
    bar.title = h.tip;
    box.append(bar);
    if (i % 6 === 0 || i === b.hours.length - 1) axis.append(el('span', '', h.label + ' 点'));
  });
  $('byhour-text').textContent = b.text;
}

function renderDisconnects(rows) {
  const list = $('disconnects');
  list.replaceChildren();
  if (!rows.length) {
    list.append(el('li', 'empty', '最近 7 天没有断联。'));
    return;
  }
  for (const r of rows) {
    const li = el('li');
    const row = el('div', 'row');
    const what = el('span', 'what', r.domain);
    if (r.count > 1) what.append(el('small', '', r.count + ' 条'));
    row.append(el('span', 'when', r.time.slice(5, 16)), what, el('span', 'badge c-' + r.cause, r.cause_label));
    const why = el('div', 'why clamp', r.error + (r.why ? '：' + r.why : ''));
    why.title = '点一下展开';
    why.addEventListener('click', () => why.classList.toggle('clamp'));
    li.append(row, why);
    if (r.raw) li.append(el('div', 'raw', r.raw));
    list.append(li);
  }
}

function renderEvents(rows) {
  const list = $('events');
  list.replaceChildren();
  if (!rows.length) {
    list.append(el('li', 'empty', '最近 24 小时没有事件。'));
    return;
  }
  for (const e of rows) {
    const li = el('li');
    const row = el('div', 'row');
    row.append(el('span', 'when', e.time.slice(11, 19)), el('span', 'label', e.label), el('span', 'what', e.text));
    li.append(row);
    list.append(li);
  }
}

function renderHistory() {
  if (!hist) return;
  renderSummary(period === 'day' ? hist.day : hist.week);
  renderHours(hist.hours);
  renderByHour(hist.by_hour);
  renderDisconnects(hist.disconnects);
  renderEvents(hist.events);
}

function setPeriod(p) {
  period = p;
  for (const id of ['day', 'week']) {
    const b = $('tab-' + id);
    b.classList.toggle('on', id === p);
    b.setAttribute('aria-pressed', id === p ? 'true' : 'false');
  }
  renderHistory();
}

// ---- 操作 ----

function toast(text, bad) {
  const t = $('toast');
  t.textContent = text;
  t.classList.toggle('bad', !!bad);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.hidden = true;
  }, 6000);
}

async function act(button) {
  button.disabled = true;
  try {
    const r = await api('/api/action', { action: button.dataset.action });
    toast(r.message, false);
    refresh();
  } catch (e) {
    if (e.expired) gate('面板会话已失效。请点托盘里的 AI Anchor 图标重新打开。');
    else toast(e.message, true);
  } finally {
    button.disabled = false;
  }
}

// ---- 轮询 ----

async function refresh() {
  try {
    renderState(await api('/api/state'));
    if (failures) ungate();
    failures = 0;
    if (performance.now() - histAt >= HISTORY_EVERY_MS || !hist) {
      histAt = performance.now();
      const h = await api('/api/history');
      const key = JSON.stringify(h);
      if (key !== lastHist) {
        lastHist = key;
        hist = h;
        renderHistory();
      }
    }
  } catch (e) {
    if (e.expired) {
      gate('面板会话已失效。请点托盘里的 AI Anchor 图标重新打开。');
      return false;
    }
    failures += 1;
    // 连续几次都连不上：用户代理退出了，或者面板服务因为空闲停了
    if (failures >= 3) gate('连不上 AI Anchor 用户代理。它可能已经退出或重启了：请点托盘里的 AI Anchor 图标重新打开面板。');
  }
  return true;
}

async function loop() {
  const go = await refresh();
  if (!go) return;
  setTimeout(loop, document.hidden ? HIDDEN_EVERY_MS : STATE_EVERY_MS);
}

async function start() {
  const m = /[#&]k=([0-9a-f]{32})/.exec(location.hash);
  if (m) {
    // 入场券只能用一次：换成会话令牌后就从地址里去掉
    history.replaceState(null, '', location.pathname);
    try {
      const r = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket: m[1] }),
        cache: 'no-store',
      });
      if (r.ok) {
        token = (await r.json()).token;
        sessionStorage.setItem(KEY, token);
      }
    } catch (_) {
      token = null;
    }
  }
  if (!token) token = sessionStorage.getItem(KEY);
  if (!token) {
    gate('请点托盘里的 AI Anchor 图标打开面板，或者运行 anchor panel。这个地址不能直接打开。');
    return;
  }
  ungate();
  for (const b of document.querySelectorAll('button[data-action]')) b.addEventListener('click', () => act(b));
  $('tab-day').addEventListener('click', () => setPeriod('day'));
  $('tab-week').addEventListener('click', () => setPeriod('week'));
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && token) refresh();
  });
  setInterval(renderTimer, 1000);
  loop();
}

start();
