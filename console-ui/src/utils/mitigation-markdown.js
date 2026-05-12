/**
 * Convert a mitigation's implementation guidance to a clean Markdown block.
 *
 * Splits the guidance on the LLM's preferred numbered-step delimiters
 * ("1) ..." / "1. ...") so the output is a real list rather than one long
 * paragraph — friendly for pasting into Notion, Linear, Jira, or a Markdown
 * note. Falls back to a single paragraph when no numbered structure is
 * detected.
 */
export function mitigationToMarkdown(mitigation) {
  const name = (mitigation?.name || 'Mitigation').trim();
  const technique = mitigation?.techniqueId ? ` (\`${mitigation.techniqueId}\`)` : '';
  const guidance = (mitigation?.description || '').trim();

  let body;
  if (!guidance) {
    body = '_No implementation guidance available._';
  } else {
    const parts = guidance.split(/(?:^|\s)(\d+)[.)]\s+/);
    if (parts.length >= 5) {
      const items = [];
      for (let i = 1; i < parts.length - 1; i += 2) {
        const content = (parts[i + 1] || '').trim();
        if (content) items.push(content);
      }
      const preamble = (parts[0] || '').trim();
      body = [
        preamble,
        ...items.map((step, i) => `${i + 1}. ${step}`),
      ].filter(Boolean).join('\n');
    } else {
      body = guidance;
    }
  }

  return `## ${name}${technique}\n\n${body}\n`;
}
