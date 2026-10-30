import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync, strToU8 } from 'fflate';
import { OpenXmlOfficeAdapter } from '../src/office.js';

const adapter = new OpenXmlOfficeAdapter();
function office(entries: Record<string, string>) {
  return zipSync(Object.fromEntries(Object.entries(entries).map(([path, value]) => [path, strToU8(value)])));
}

test('production Office extraction handles paragraphs, slide order, and spreadsheet shared strings', async () => {
  const word = await adapter.extract({ filename: 'context.docx', bytes: office({
    'word/document.xml': '<w:document xmlns:w="word"><w:p><w:r><w:t>Patient &amp; payment</w:t></w:r><w:r><w:t> records</w:t></w:r></w:p></w:document>',
  }) });
  assert.equal(word.pages[0]!.lines[0]!.text, 'Patient & payment records');
  const slides = await adapter.extract({ filename: 'context.pptx', bytes: office({
    'ppt/slides/slide10.xml': '<p xmlns:a="drawing"><a:p><a:t>Later</a:t></a:p></p>',
    'ppt/slides/slide2.xml': '<p xmlns:a="drawing"><a:p><a:t>Earlier</a:t></a:p></p>',
  }) });
  assert.deepEqual(slides.pages.map(page => page.lines[0]!.text), ['Earlier', 'Later']);
  const sheet = await adapter.extract({ filename: 'assets.xlsx', bytes: office({
    'xl/sharedStrings.xml': '<sst><si><t>Payment API</t></si></sst>',
    'xl/worksheets/sheet1.xml': '<worksheet><row><c r="A1" t="s"><v>0</v></c><c r="B1"><v>123</v></c></row></worksheet>',
  }) });
  assert.equal(sheet.pages[0]!.lines[0]!.text, 'A1: Payment API\tB1: 123');
});

test('Office XML fails closed on DTDs, malformed XML, and legacy binary formats', async () => {
  for (const xml of ['<!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>', '<a><b></a>']) {
    await assert.rejects(adapter.extract({ filename: 'bad.docx', bytes: office({ 'word/document.xml': xml }) }));
  }
  await assert.rejects(adapter.extract({ filename: 'old.doc', bytes: Uint8Array.of(0xd0, 0xcf) }), /Legacy binary/);
});
