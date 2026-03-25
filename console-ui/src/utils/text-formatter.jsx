import React from 'react';

/**
 * Render inline formatting within a text segment:
 * - **bold** → <strong>
 * - `code` → <code>
 */
export function renderInlineFormatting(text, keyPrefix) {
  if (!text) return null;
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={`${keyPrefix}-${i}`}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={`${keyPrefix}-${i}`} style={{ background: '#f2f3f3', padding: '1px 4px', borderRadius: 3, fontFamily: 'monospace' }}>
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

/**
 * Render implementation guidance text with structure:
 * - Splits numbered steps (1. 2. 3.) into an ordered list
 * - Splits on newlines for paragraph breaks
 * - Applies inline formatting (**bold**, `code`)
 */
export function renderFormattedText(text) {
  if (!text) return null;

  // Try to split on numbered steps: "1. ... 2. ... 3. ..."
  const numberedParts = text.split(/(?:^|\s)(\d+)\.\s+/);

  // If we found numbered steps (at least 2 items), render as ordered list
  if (numberedParts.length >= 5) {
    const items = [];
    for (let i = 1; i < numberedParts.length - 1; i += 2) {
      const content = (numberedParts[i + 1] || '').trim();
      if (content) {
        items.push(content);
      }
    }
    if (items.length >= 2) {
      const preamble = numberedParts[0]?.trim();
      return (
        <>
          {preamble && <div style={{ marginBottom: '8px' }}>{renderInlineFormatting(preamble, 'pre')}</div>}
          <ol style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {items.map((item, i) => (
              <li key={i}>{renderInlineFormatting(item, `li-${i}`)}</li>
            ))}
          </ol>
        </>
      );
    }
  }

  // Fallback: split on newlines for paragraph breaks
  const lines = text.split(/\n+/);
  if (lines.length > 1) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {lines.map((line, i) => (
          <div key={i}>{renderInlineFormatting(line.trim(), `p-${i}`)}</div>
        ))}
      </div>
    );
  }

  return renderInlineFormatting(text, 'txt');
}
