// SPDX-License-Identifier: Apache-2.0
import hljs from './vendor/highlight.js';

const excluded = /\.(?:docx?|od[tpstfg]|rtf|pptx?|xlsx?|pdf|epub|zip|rar|7z|gz|bz2|xz|tar|exe|dll|wasm|png|jpe?g|gif|webp|ico|bmp|avif|heic|mp[34]|mov|mkv|wav|ogg|flac|woff2?|ttf)$/i;
const languages = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript', py: 'python', pyw: 'python',
  c: 'c', h: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
  cs: 'csharp', java: 'java', kt: 'kotlin', kts: 'kotlin', go: 'go', rs: 'rust',
  rb: 'ruby', php: 'php', swift: 'swift', sh: 'bash', bash: 'bash', zsh: 'bash',
  html: 'xml', htm: 'xml', xml: 'xml', svg: 'xml', vue: 'xml', svelte: 'xml',
  css: 'css', scss: 'scss', less: 'less', json: 'json', jsonl: 'json',
  yml: 'yaml', yaml: 'yaml', toml: 'ini', ini: 'ini', sql: 'sql',
  md: 'markdown', markdown: 'markdown', diff: 'diff', patch: 'diff',
  lua: 'lua', pl: 'perl', r: 'r', mk: 'makefile',
};

export function canPreviewText(name, type = '') {
  if (excluded.test(name)) return false;
  if (/^(?:audio|video|font)\//i.test(type)) return false;
  if (/^image\//i.test(type) && type !== 'image/svg+xml') return false;
  return !/(?:officedocument|opendocument|msword|ms-excel|ms-powerpoint|application\/pdf|application\/rtf)/i.test(type);
}

export function languageFor(name) {
  const base = name.split(/[\\/]/).pop().toLowerCase();
  if (/^(?:makefile|gnumakefile)$/.test(base)) return 'makefile';
  const language = languages[base.split('.').pop()];
  return language && hljs.getLanguage(language) ? language : null;
}

export function decodeText(bytes) {
  // Office containers and common binaries must never become apparent text.
  if ((bytes[0] === 0x50 && bytes[1] === 0x4b &&
       [[3,4],[5,6],[7,8]].some(([a,b]) => bytes[2] === a && bytes[3] === b)) ||
      (bytes[0] === 0xd0 && bytes[1] === 0xcf) ||
      (bytes[0] === 0x7f && bytes[1] === 0x45)) throw new Error('binary');
  let encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le'
    : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : 'utf-8';
  let text;
  try { text = new TextDecoder(encoding, {fatal: true}).decode(bytes); }
  catch {
    if (encoding !== 'utf-8') throw new Error('encoding');
    encoding = 'windows-1251';
    text = new TextDecoder(encoding, {fatal: true}).decode(bytes);
  }
  if (/[\u0000-\u0008\u000e-\u001f\u007f]/.test(text) || /^(?:%PDF-|\{\\rtf)/.test(text)) throw new Error('binary');
  return {text, encoding};
}

export function renderText(target, text, name) {
  const language = languageFor(name);
  // Keep the entire file readable; bound syntax parsing/DOM expansion, not content.
  const highlighted = Boolean(language && text.length <= 200000);
  target.textContent = text;
  if (highlighted) {
    try {
      // Only the pinned highlighter's escaped output is HTML; source is never HTML.
      target.innerHTML = hljs.highlight(text, {language, ignoreIllegals: true}).value;
    } catch { target.textContent = text; return {language, highlighted: false}; }
  }
  return {language, highlighted};
}
