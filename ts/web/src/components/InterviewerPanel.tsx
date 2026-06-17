'use client';

import { useState, useRef, useEffect, type ReactNode } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Button from '@cloudscape-design/components/button';
import Textarea, { type TextareaProps } from '@cloudscape-design/components/textarea';
import Box from '@cloudscape-design/components/box';

/**
 * Render a plain-text string with basic inline formatting:
 * - Newlines become <br/>
 * - **bold** becomes <strong>
 * - `code` becomes <code>
 */
function renderText(text: string | undefined): ReactNode {
  if (!text) return null;
  // Split by newlines, then handle inline formatting per line
  return text.split('\n').map((line, i, arr) => {
    // Replace **bold** and `code`
    const parts: ReactNode[] = [];
    const remaining = line;
    let key = 0;
    const regex = /(\*\*(.+?)\*\*|`(.+?)`)/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;
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

/** A single message in the interviewer chat transcript. */
export interface InterviewerChatEntry {
  role: 'agent' | 'user';
  message?: string;
  questions?: string[];
  text?: string;
}

export interface InterviewerPanelProps {
  chatHistory?: InterviewerChatEntry[];
  onSubmit: (text: string) => void;
  onSkip: () => void;
  onBack?: () => void;
  /** True when waiting for agent response after submit. */
  waiting?: boolean;
}

/**
 * InterviewerPanel — inline chat panel for the context validation stage.
 */
export default function InterviewerPanel({
  chatHistory = [],
  onSubmit,
  onSkip,
  onBack,
  waiting = false,
}: InterviewerPanelProps) {
  const [inputValue, setInputValue] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistory]);

  function handleSubmit() {
    const text = inputValue.trim();
    if (!text) return;
    onSubmit(text);
    setInputValue('');
  }

  const handleKeyDown: TextareaProps['onKeyDown'] = (e) => {
    if (e.detail.key === 'Enter' && !e.detail.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

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
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px' }}>
            <div>
              {onBack && (
                <Button
                  variant="link"
                  onClick={onBack}
                  disabled={waiting}
                  iconName="arrow-left"
                  data-testid="interviewer-back"
                >
                  Back to scanner review
                </Button>
              )}
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button
                variant="link"
                onClick={onSkip}
                disabled={waiting}
                data-testid="interviewer-skip"
              >
                Skip
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
        </div>
      </SpaceBetween>
    </Container>
  );
}
