import { SaxesParser } from 'saxes';
import { SafeZipExtractor } from './archive.js';
import type { OcrDocument, OfficeDocumentAdapter } from './extractors.js';

/** Text-only OOXML extraction. Never follows relationships or executes macros. */
export class OpenXmlOfficeAdapter implements OfficeDocumentAdapter {
  async extract(input: { bytes: Uint8Array; filename: string }): Promise<OcrDocument> {
    if (input.bytes[0] !== 0x50 || input.bytes[1] !== 0x4b) {
      throw new Error('Legacy binary Office files are unsupported. Export as DOCX, PPTX, XLSX, PDF, or text.');
    }
    const { entries } = new SafeZipExtractor({
      maximumExpandedBytes: 128 * 1024 * 1024,
      maximumFileBytes: 16 * 1024 * 1024,
      maximumArchiveNesting: 0,
    }).extract(input.bytes);
    const shared = entries.find(entry => entry.path === 'xl/sharedStrings.xml');
    const strings = shared ? textBlocks(shared.bytes, 'si') : [];
    const documents = entries.filter(entry =>
      entry.path === 'word/document.xml' ||
      /^ppt\/slides\/slide\d+\.xml$/.test(entry.path) ||
      /^xl\/worksheets\/sheet\d+\.xml$/.test(entry.path),
    ).sort((a, b) => a.path.localeCompare(b.path, 'en', { numeric: true }));
    if (!documents.length) throw new Error('No supported Office document body found');
    return {
      pages: documents.map((entry, index) => ({
        // Word = document body; PPTX = slide; XLSX = worksheet. These are
        // logical extraction sections, not inferred printed page positions.
        pageNumber: index + 1,
        lines: (entry.path.startsWith('xl/') ? sheetRows(entry.bytes, strings) : textBlocks(entry.bytes, 'p'))
          .filter(text => text.trim()).map((text, line) => ({
            text, lineNumber: line + 1, confidence: 1,
          })),
      })),
    };
  }
}

function parser(bytes: Uint8Array): { xml: string; sax: SaxesParser } {
  const xml = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const sax = new SaxesParser();
  sax.on('doctype', () => { throw new Error('Office XML must not contain a document type declaration'); });
  return { xml, sax };
}

function local(name: string): string { return name.split(':').at(-1)!; }

function textBlocks(bytes: Uint8Array, boundary: string): string[] {
  const { xml, sax } = parser(bytes);
  const output: string[] = [];
  let text = '';
  let inText = false;
  sax.on('opentag', tag => {
    const name = local(tag.name);
    if (name === 't') inText = true;
    if (name === 'tab') text += '\t';
    if (name === 'br') text += '\n';
  });
  sax.on('text', value => { if (inText) text += value; });
  sax.on('closetag', tag => {
    const name = local(tag.name);
    if (name === 't') inText = false;
    if (name === boundary) { output.push(text); text = ''; }
  });
  sax.write(xml).close();
  return output;
}

function sheetRows(bytes: Uint8Array, shared: readonly string[]): string[] {
  const { xml, sax } = parser(bytes);
  const rows: string[] = [];
  let cells: string[] = [];
  let value = '';
  let cellType = '';
  let cellRef = '';
  let inValue = false;
  sax.on('opentag', tag => {
    const name = local(tag.name);
    if (name === 'c') {
      cellType = String(tag.attributes['t'] ?? '');
      cellRef = String(tag.attributes['r'] ?? '');
      value = '';
    }
    if (name === 'v' || name === 't') inValue = true;
  });
  sax.on('text', text => { if (inValue) value += text; });
  sax.on('closetag', tag => {
    const name = local(tag.name);
    if (name === 'v' || name === 't') inValue = false;
    if (name === 'c') {
      if (cellType === 's') {
        const index = Number(value);
        if (!Number.isInteger(index) || shared[index] === undefined) throw new Error('Invalid Office shared-string reference');
        value = shared[index]!;
      }
      cells.push(`${cellRef}: ${value}`);
    }
    if (name === 'row') { rows.push(cells.join('\t')); cells = []; }
  });
  sax.write(xml).close();
  return rows;
}
