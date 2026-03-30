import { useState, useRef, useEffect } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Button from '@cloudscape-design/components/button';
import Textarea from '@cloudscape-design/components/textarea';
import Box from '@cloudscape-design/components/box';

/**
 * Render a plain-text string with basic inline formatting:
 * - Newlines become <br/>
 * - **bold** becomes <strong>
 * - `code` becomes <code>
 */
function renderText(text) {
  if (!text) return null;
  // Split by newlines, then handle inline formatting per line
  return text.split('\n').map((line, i, arr) => {
    // Replace **bold** and `code`
    const parts = [];
    let remaining = line;
    let key = 0;
    const regex = /(\*\*(.+?)\*\*|`(.+?)`)/g;
    let lastIndex = 0;
    let match;
    while ((match = regex.exec(remaining)) !== null) {
      if (match.index > lastIndex) {
        parts.push(remaining.slice(lastIndex, match.index));
      }
      if (match[2]) {
        parts.push(<strong key={key++}>{match[2]}</strong>);
      } else if (match[3]) {
        parts.push(<code key={key++} style={{ background: '#e8e8e8', padding: '1px 4px', borderRadius: '3px', fontSize: '0.9em' }}>{match[3]}</code>);
      }
      lastIndex = match.index + match[0].length;
    }
    if (lastIndex < remaining.length) {
      parts.push(remaining.slice(lastIndex));
    }
    return (
      <span key={i}>
        {parts.length > 0 ? parts : line}
        {i < arr.length - 1 && <br />}
      </span>
    );
  });
}

/**
 * InterviewerPanel — inline chat panel for the context validation stage.
 *
 * @param {Object} props
 * @param {Array} props.chatHistory - Array of { role: 'agent'|'user', message?, questions?, text? }
 * @param {Function} props.onSubmit - Called with the user's response text
 * @param {Function} props.onSkip - Called when user wants to proceed without answering
 * @param {boolean} props.waiting - True when waiting for agent response after submit
 */
export default function InterviewerPanel({ chatHistory = [], onSubmit, onSkip, waiting = false }) {
  const [inputValue, setInputValue] = useState('');
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistory]);

  function handleSubmit() {
    const text = inputValue.trim();
    if (!text) return;
    onSubmit(text);
    setInputValue('');
  }

  function handleKeyDown(e) {
    if (e.detail.key === 'Enter' && !e.detail.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }

  return (
    <Container
      header={<Header variant="h3">Context Validation</Header>}
      data-testid="interviewer-panel"
    >
      <SpaceBetween size="m">
        {/* Chat history */}
        <div style={{ maxHeight: '400px', overflowY: 'auto', padding: '4px' }}>
          <SpaceBetween size="s">
            {chatHistory.map((entry, i) => (
              <div key={i} style={{
                padding: '10px 14px',
                borderRadius: '8px',
                background: entry.role === 'agent' ? '#f0f4f8' : '#e8f4fd',
                borderLeft: entry.role === 'agent' ? '3px solid #0972d3' : '3px solid #037f0c',
              }}>
                <Box fontSize="body-s" color="text-status-inactive" margin={{ bottom: 'xxxs' }}>
                  {entry.role === 'agent' ? 'Interviewer' : 'You'}
                </Box>
                {entry.role === 'agent' && (
                  <>
                    {entry.message && (
                      <Box margin={{ bottom: 'xs' }}>{renderText(entry.message)}</Box>
                    )}
                    {entry.questions && entry.questions.length > 0 && (
                      <ol style={{ margin: '4px 0 0 0', paddingLeft: '20px' }}>
                        {entry.questions.map((q, qi) => (
                          <li key={qi} style={{ marginBottom: '8px', lineHeight: '1.5' }}>
                            {renderText(q)}
                          </li>
                        ))}
                      </ol>
                    )}
                  </>
                )}
                {entry.role === 'user' && (
                  <Box>{renderText(entry.text)}</Box>
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </SpaceBetween>
        </div>

        {/* Input area */}
        <div>
          <Textarea
            value={inputValue}
            onChange={({ detail }) => setInputValue(detail.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type your response..."
            rows={3}
            disabled={waiting}
            data-testid="interviewer-input"
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
            <Button
              variant="link"
              onClick={onSkip}
              disabled={waiting}
              data-testid="interviewer-skip"
            >
              Ready to proceed
            </Button>
            <Button
              variant="primary"
              onClick={handleSubmit}
              disabled={waiting || !inputValue.trim()}
              loading={waiting}
              data-testid="interviewer-submit"
            >
              Submit
            </Button>
          </div>
        </div>
      </SpaceBetween>
    </Container>
  );
}
