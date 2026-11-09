// SPDX-License-Identifier: Apache-2.0
// Read-only visitor UI. All untrusted strings are rendered with textContent.
'use strict';
const $ = id => document.getElementById(id);
let entries = [], selected = null, requestVersion = 0, pinnedKey = '', servedProof = null, loadedProof = null;
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined && text !== null) n.textContent = String(text); if (cls) n.className = cls; return n; };
const fold = value => String(value).normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
const kb = n => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';
const kindLabel = e => e.kind === 'word' ? 'Word · ' + e.language : 'Character';
async function api(path) {
  const r = await fetch(path, {cache: 'no-store', credentials: 'omit'});
  if (!r.ok) throw new Error('Could not load ' + path + ' (HTTP ' + r.status + ').');
  return r.json();
}
let toastTimer = 0;
function toast(text) { const t = $('toast'); t.textContent = text; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 2200); }
function fail(error) { $('error').textContent = error.message || 'The verified snapshot is unavailable.'; $('error').hidden = false; $('entry').setAttribute('aria-busy', 'false'); }
function fact(label, value, wide) { const d = el('div', undefined, wide ? 'span' : undefined); d.append(el('span', label, 'k'), el('span', value, 'v')); return d; }

function renderList() {
  const q = fold($('search').value.trim());
  const matches = entries.filter(e => !q || fold(e.id).includes(q) || e.root.includes(q));
  const list = $('entries'); list.replaceChildren();
  $('catalog-status').textContent = matches.length === entries.length ? entries.length + ' minted entries' : matches.length + ' of ' + entries.length + ' entries';
  for (const entry of matches) {
    const li = el('li');
    const b = el('button', undefined, 'entry-button'); b.type = 'button';
    b.setAttribute('aria-pressed', String(entry.root === selected));
    const label = el('span'); label.append(el('span', entry.id, 'entry-name'), el('span', kindLabel(entry) + (entry.dependency_count ? ' · ' + entry.dependency_count + ' characters' : ''), 'entry-kind'));
    b.append(label, el('span', entry.state, 'pill' + (entry.state === 'minted' ? ' good' : '')));
    b.addEventListener('click', () => select(entry.root, true));
    li.append(b); list.append(li);
  }
}

async function select(root, focus) {
  const version = ++requestVersion; selected = root; renderList();
  const panel = $('entry'); panel.setAttribute('aria-busy', 'true');
  try {
    const data = await api('/api/entry/' + root); if (version !== requestVersion) return;
    panel.replaceChildren();
    const top = el('div', undefined, 'entry-top');
    top.append(el('span', kindLabel(data), 'pill'), el('span', 'Verified · ' + data.state, 'pill good'));
    panel.append(top, el('h2', data.id, 'entry-title'));
    panel.append(el('p', data.kind === 'word'
      ? 'This word was minted after the characters below. Its proof carries each of them, so the whole word can be checked offline.'
      : 'This character has its own signed draft, validation and native mint.', 'muted'));
    const s = data.summary || {}; const senses = s.senses || []; const translations = s.translations || [];
    if (senses.length || translations.length) {
      panel.append(el('p', 'Meaning in this entry (as authored, not verified as true)', 'label'));
      for (const leaf of senses.slice(0, 2)) panel.append(el('p', leaf.value || leaf.gloss || '', 'meaning'));
      if (translations.length) panel.append(el('p', 'Translations: ' + translations.slice(0, 5).map(l => (l.lang ? l.lang + ': ' : '') + l.value).join(' · '), 'muted small'));
    }
    const facts = el('dl', undefined, 'facts');
    facts.append(
      fact('State', data.state),
      fact('Signed outcome', '#' + data.signed_sequence),
      fact('Native mint block', '#' + data.native_sequence),
      fact('Depends on', data.dependencies.length ? data.dependencies.length + ' characters' : 'nothing (base layer)'));
    panel.append(facts);
    panel.append(el('p', 'Content root (identity)', 'label'), el('code', data.root, 'root'));
    if (data.dependencies.length) {
      panel.append(el('p', 'Dependency closure · tap a character', 'label'));
      const deps = el('div', undefined, 'deps');
      for (const dep of data.dependencies) {
        const b = el('button', undefined, 'dep'); b.type = 'button';
        b.append(el('strong', dep.char), el('span', 'block ' + dep.block));
        b.setAttribute('aria-label', 'Show character ' + dep.char + ', minted in block ' + dep.block);
        b.addEventListener('click', () => select(dep.root, true));
        deps.append(b);
      }
      panel.append(deps);
    }
    const tech = el('details'); tech.append(el('summary', 'Technical evidence'));
    tech.append(el('p', 'Native block hash (block commitment, not a separate block signature)', 'label'), el('code', data.native_block_hash, 'root'),
      el('p', 'Pinned signer key', 'label'), el('code', data.expected_signer, 'root'),
      el('p', 'Public entry and dependency references', 'label'),
      el('pre', JSON.stringify({identity: {kind: data.kind, language: data.language}, dependencies: data.dependencies, content: data.content}, null, 2)));
    panel.append(tech);
    panel.setAttribute('aria-busy', 'false');
    if (focus && window.matchMedia('(max-width: 959px)').matches) { panel.focus({preventScroll: true}); panel.scrollIntoView({block: 'start'}); }
  } catch (error) { if (version === requestVersion) fail(error); }
}

function renderGlance(t) {
  const g = $('glance'); g.replaceChildren();
  const chip = (text, root, cls, label) => { const b = el('button', text, 'g' + (cls ? ' ' + cls : '')); b.type = 'button'; b.setAttribute('aria-label', label); b.addEventListener('click', () => { select(root, false); $('explore').scrollIntoView({block: 'start'}); }); return b; };
  (t.dependencies || []).forEach((d, i) => { if (i) g.append(el('span', '+', 'op')); g.append(chip(d.char, d.root, '', 'Show character ' + d.char)); });
  if ((t.dependencies || []).length) g.append(el('span', '→', 'op'));
  g.append(chip(t.id, t.root, 'word', 'Show ' + kindLabel(t).toLowerCase() + ' ' + t.id));
}
function setProofSource(src) {
  loadedProof = src;
  $('proof-meta').textContent = src ? src.label + ' · ' + kb(src.text.length) + ' loaded' : '';
  $('clear-proof').hidden = !src;
  if (src) $('proof-text').value = '';
}
function showResult(ok, title, lines, facts) {
  const box = $('verify-result'); box.replaceChildren(); box.className = 'result ' + (ok ? 'good' : 'bad');
  box.append(el('h3', title));
  for (const line of lines) box.append(el('p', line, 'small'));
  if (facts && facts.length) { const dl = el('dl', undefined, 'facts'); for (const f of facts) dl.append(fact(f[0], f[1], f[2])); box.append(dl); }
  box.hidden = false; box.scrollIntoView({block: 'nearest'});
}
async function verify() {
  const text = $('proof-text').value.trim() || (loadedProof && loadedProof.text) || '';
  const key = $('key').value.replace(/\s+/g, '');
  if (!text) return showResult(false, 'Add a proof first', ['Paste proof JSON, upload a file, or tap “Use the served proof”.']);
  if (!key) return showResult(false, 'Add the expected key', ['Enter the public key you expect the proof to be signed by.']);
  try { JSON.parse(text); } catch (_) { return showResult(false, 'Not valid JSON', ['The proof text could not be parsed as JSON.']); }
  const btn = $('verify-btn'); btn.disabled = true; btn.textContent = 'Checking signatures…';
  try {
    const r = await fetch('/api/verify', {method: 'POST', cache: 'no-store', credentials: 'omit', headers: {'Content-Type': 'application/json'}, body: '{"expected_key":' + JSON.stringify(key) + ',"proof":' + text + '}'});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return showResult(false, 'Request refused', [data.error || ('HTTP ' + r.status)]);
    if (data.valid) {
      const v = data.result; const id = v.identity && (v.identity.spelling || v.identity.text) || '';
      const deps = (v.dependencies || []).map(d => d.char).join(' ');
      showResult(true, 'Valid proof' + (id ? ': ' + id : ''), [
        'Every signature matches the expected key, the block payloads match, and the dependency closure is complete.',
        'Scope: ' + v.scope + '.'],
        [['State', v.attested_state], ['Last signed event', '#' + v.at_sequence], ['Characters', v.dependency_count ? v.dependency_count + (deps ? ' (' + deps + ')' : '') : 'none'], ['Root', v.root, true]]);
    } else {
      showResult(false, 'Not valid', [data.reason || 'The proof did not verify.', 'A wrong key, an edited byte, or a missing dependency makes the check fail.']);
    }
  } catch (error) {
    showResult(false, 'Could not reach the local server', [error.message || 'Network error']);
  } finally { btn.disabled = false; btn.textContent = 'Verify proof'; }
}

async function copyFrom(id) {
  const text = $(id).textContent;
  try { await navigator.clipboard.writeText(text); toast('Copied'); }
  catch (_) { const r = document.createRange(); r.selectNodeContents($(id)); const s = getSelection(); s.removeAllRanges(); s.addRange(r); toast('Selected. Copy it from the menu.'); }
}

async function loadPackage() {
  try {
    const p = await api('/api/package');
    if (!p.available) { $('pkg-note').textContent = 'This local server was started without the package file, so there is no download here. The name and checksum above are for the b859a2f build.'; return; }
    const dir = p.name.replace(/\.tar\.gz$/, '');
    $('pkg-name').textContent = p.name; $('pkg-size').textContent = kb(p.size); $('pkg-sha').textContent = p.sha256;
    const a = $('pkg-download'); a.setAttribute('download', p.name); a.hidden = false;
    $('pkg-note').textContent = 'SHA-256 computed by this server from the file it serves' + (p.sidecar_matched ? ' and matched against its .sha256 file.' : '.') + ' Check it again after downloading.';
    $('qs-1').textContent = 'echo "' + p.sha256 + '  ' + p.name + '" | sha256sum -c -';
    $('qs-2').textContent = 'tar -xzf ' + p.name + '\ncd ' + dir;
  } catch (_) { $('pkg-note').textContent = 'Package details are unavailable.'; }
}

document.addEventListener('click', e => { const b = e.target.closest('[data-copy]'); if (b) copyFrom(b.getAttribute('data-copy')); });
$('search').addEventListener('input', renderList);
$('verify-btn').addEventListener('click', verify);
$('proof-text').addEventListener('input', () => { if ($('proof-text').value) setProofSource(null); });
$('clear-proof').addEventListener('click', () => { setProofSource(null); $('proof-text').value = ''; $('verify-result').hidden = true; });
$('proof-file').addEventListener('change', async ev => {
  const f = ev.target.files && ev.target.files[0]; if (!f) return;
  if (f.size > 8 * 1048576) { showResult(false, 'File too large', ['Proofs up to 8 MB can be checked here.']); return; }
  setProofSource({label: f.name, text: await f.text()}); ev.target.value = '';
});
$('use-served').addEventListener('click', async () => {
  try {
    if (!servedProof) { const r = await fetch('/proof.json', {cache: 'no-store', credentials: 'omit'}); if (!r.ok) throw new Error('HTTP ' + r.status); servedProof = await r.text(); }
    setProofSource({label: 'Served proof', text: servedProof});
  } catch (error) { showResult(false, 'Could not load the served proof', [error.message]); }
});
$('use-demo-key').addEventListener('click', () => { $('key').value = pinnedKey; });
$('use-wrong-key').addEventListener('click', () => {
  const base = $('key').value.replace(/\s+/g, '') || pinnedKey; if (!base) return;
  const last = base.slice(-1); $('key').value = base.slice(0, -1) + (last === '0' ? '1' : '0');
  toast('Changed the last character of the key');
});

(async () => {
  loadPackage();
  try {
    const [data, v] = await Promise.all([api('/api/entries'), api('/api/verification')]);
    entries = data.entries.sort((a, b) => (a.kind === 'word' ? 0 : 1) - (b.kind === 'word' ? 0 : 1) || a.id.localeCompare(b.id));
    pinnedKey = v.expected_signer || '';
    const id = v.identity && v.identity.spelling || '';
    $('status').classList.add('ok');
    $('status-title').textContent = 'Served proof verified' + (id ? ': ' + id : '');
    $('status-detail').textContent = entries.length + ' minted entries · pinned key ' + pinnedKey.slice(0, 12) + '… · last signed event #' + v.at_sequence;
    try { renderGlance(await api('/api/entry/' + data.target_root)); } catch (_) { /* optional summary */ }
    await select(data.target_root, false);
  } catch (error) {
    fail(error); $('status').classList.add('bad');
    $('status-title').textContent = 'No verified data loaded'; $('status-detail').textContent = 'Nothing is shown instead of unverified data.';
    $('catalog-status').textContent = 'No verified data loaded.';
  }
})();
