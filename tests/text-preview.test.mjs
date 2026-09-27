import test from 'node:test';
import assert from 'node:assert/strict';
import {canPreviewText, decodeText, languageFor, renderText} from '../web/text-preview.js';
const bytes = text => new TextEncoder().encode(text);

test('text candidates include unknown extensions and extensionless files, exclude office/media', () => {
  for (const name of ['source.py', '.env', 'LICENSE', 'custom.unknown', 'page.html', 'icon.svg']) assert.equal(canPreviewText(name), true);
  for (const name of ['a.doc', 'a.DOCX', 'a.odt', 'a.rtf', 'a.pdf', 'a.zip', 'a.png']) assert.equal(canPreviewText(name, 'text/plain'), false);
  assert.equal(canPreviewText('no-extension', 'application/vnd.oasis.opendocument.text'), false);
});
test('full Unicode text, BOM UTF-16 and Windows-1251 decode without truncation', () => {
  const text = 'Привет 🗝️\n'.repeat(50000) + 'THE END';
  assert.equal(decodeText(bytes(text)).text, text);
  assert.equal(decodeText(new Uint8Array([255,254,65,0,10,0])).text, 'A\n');
  assert.equal(decodeText(new Uint8Array([254,255,0,65])).text, 'A');
  assert.equal(decodeText(new Uint8Array([207,240,232,226,229,242])).text, 'Привет');
  assert.equal(decodeText(new Uint8Array()).text, '');
  assert.equal(decodeText(bytes('PK is plain text')).text, 'PK is plain text');
});
test('binary/control content and renamed formatted documents are rejected', () => {
  for (const data of [new Uint8Array([0,1,2]), bytes('PK\u0003\u0004'), bytes('%PDF-1.7'), bytes('{\\rtf1 hi}')]) assert.throws(() => decodeText(data));
});
test('major programming languages have registered grammars', () => {
  for (const name of ['a.js','a.ts','a.py','a.go','a.rs','a.c','a.cpp','a.cs','a.java','a.php','a.rb','a.swift','a.kt','a.sh','a.sql','a.html','a.css','a.json','a.yaml']) assert.ok(languageFor(name), name);
  assert.equal(languageFor('unfamiliar.ext'), null);
});
test('highlighting escapes hostile HTML; large code remains complete plain text', () => {
  const target = {textContent: '', innerHTML: ''};
  const source = '<script>alert(1)</script><img src=x onerror=alert(2)>';
  assert.equal(renderText(target, source, 'attack.html').highlighted, true);
  assert.ok(!target.innerHTML.includes('<script>'));
  assert.ok(!target.innerHTML.includes('<img '));
  const large = 'const value = 123;\n'.repeat(20000) + '// END';
  assert.equal(renderText(target, large, 'large.js').highlighted, false);
  assert.equal(target.textContent, large);
});
