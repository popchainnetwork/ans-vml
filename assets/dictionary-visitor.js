// SPDX-License-Identifier: Apache-2.0
'use strict';
const $ = id => document.getElementById(id);
let entries = [], selected = null, requestVersion = 0;
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = String(text); if (cls) n.className = cls; return n; };
const fold = value => String(value).normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
async function api(path) { const r = await fetch(path, {cache: 'no-store', credentials: 'omit'}); if (!r.ok) throw new Error('The public proof could not be loaded (' + r.status + ').'); return r.json(); }
function fail(error) { $('error').textContent = error.message || 'The verified snapshot is unavailable.'; $('error').hidden = false; $('entry').setAttribute('aria-busy', 'false'); }
function renderList() {
  const q = fold($('search').value.trim());
  const matches = entries.filter(e => fold(e.id).includes(q) || e.root.includes(q));
  $('entries').replaceChildren();
  $('catalog-status').textContent = matches.length + ' of ' + entries.length + ' proof-backed entries';
  for (const entry of matches) {
    const b = el('button', undefined, 'entry-button' + (entry.root === selected ? ' active' : ''));
    b.type = 'button'; b.setAttribute('aria-pressed', String(entry.root === selected));
    const label = el('span'); label.append(el('span', entry.id, 'entry-name'), el('span', entry.kind === 'word' ? 'Word · ' + entry.language : 'Character · Unicode', 'entry-kind'));
    b.append(label, el('span', entry.state, 'entry-state')); b.addEventListener('click', () => select(entry.root)); $('entries').append(b);
  }
}
function fact(label, value) { const node = el('div'); node.append(el('span', label, 'fact-label'), el('span', value, 'fact-value')); return node; }
async function select(root) {
  const version = ++requestVersion; selected = root; renderList(); $('entry').setAttribute('aria-busy', 'true');
  try {
    const data = await api('/api/entry/' + root); if (version !== requestVersion) return;
    const panel = $('entry'); panel.replaceChildren();
    const top = el('div', undefined, 'entry-top'); top.append(el('span', data.kind === 'word' ? 'Word · ' + data.language : 'Character · Unicode', 'tag'), el('span', 'Verified ' + data.state + ' path', 'tag verified')); panel.append(top);
    panel.append(el('h2', data.id, 'entry-title'), el('p', data.kind === 'word' ? 'This word’s native mint is bound to the previously minted characters below.' : 'This character has its own signed draft, validation, and native mint path.', 'entry-description'));
    const senses = data.summary.senses || []; const translations = data.summary.translations || [];
    if (senses.length || translations.length) {
      panel.append(el('p', 'From the selected lexical snapshot', 'meaning-label'));
      for (const leaf of senses.slice(0, 2)) panel.append(el('p', leaf.value || leaf.gloss || 'See the source leaves below.', 'meaning'));
      if (translations.length) panel.append(el('p', 'Translations in this snapshot: ' + translations.slice(0, 4).map(l => (l.lang ? l.lang + ': ' : '') + l.value).join(' · '), 'muted'));
    }
    const facts = el('div', undefined, 'fact-grid'); facts.append(fact('Lifecycle', data.state + ' · selected proof'), fact('Signed outcome', 'Sequence ' + data.signed_sequence), fact('Native mint', 'Block / event ' + data.native_sequence), fact('Dependency verification', data.dependencies.length ? data.dependencies.length + ' ordered characters verified' : 'Character base layer · no dependencies')); panel.append(facts);
    panel.append(el('p', 'Content-addressed identity', 'small-label')); const rootBox = el('div', undefined, 'root-box'); rootBox.append(el('code', data.root, 'long-value')); panel.append(rootBox);
    if (data.dependencies.length) {
      panel.append(el('p', 'Built from verified characters', 'small-label')); const deps = el('div', undefined, 'dependencies');
      for (const dep of data.dependencies) { const b = el('button', undefined, 'dependency'); b.type = 'button'; b.append(el('strong', dep.char), el('span', 'block ' + dep.block)); b.setAttribute('aria-label', 'Inspect character ' + dep.char); b.addEventListener('click', () => select(dep.root)); deps.append(b); } panel.append(deps);
    }
    const technical = el('details'); technical.append(el('summary', 'Inspect the signed evidence'));
    technical.append(el('p', 'Native block commitment (not an outer validator signature)', 'small-label'), el('code', data.native_block_hash, 'long-value'), el('p', 'Pinned expected signer', 'small-label'), el('code', data.expected_signer, 'long-value'), el('p', 'Public entry, leaves, and dependency references', 'muted'), el('pre', JSON.stringify({identity: {kind: data.kind, language: data.language}, dependencies: data.dependencies, content: data.content}, null, 2)));
    panel.append(technical); panel.setAttribute('aria-busy', 'false');
  } catch (error) { if (version === requestVersion) fail(error); }
}
$('search').addEventListener('input', renderList);
(async () => {
  try {
    const [data, verification] = await Promise.all([api('/api/entries'), api('/api/verification')]);
    entries = data.entries.sort((a, b) => (a.kind === 'word' ? 0 : 1) - (b.kind === 'word' ? 0 : 1) || a.id.localeCompare(b.id));
    $('entry-count').textContent = String(entries.length); $('signer').textContent = verification.expected_signer; $('scope').textContent = verification.scope;
    $('verification-status').textContent = 'Pinned signer matched · ' + (verification.word_dependency_path_verified ? 'Word and character dependency paths verified' : 'Character path verified') + ' · signed sequence ' + verification.at_sequence;
    await select(data.target_root);
  } catch (error) { fail(error); $('catalog-status').textContent = 'No verified data loaded.'; $('verification-status').textContent = 'Verification unavailable. No fallback data is shown.'; }
})();
