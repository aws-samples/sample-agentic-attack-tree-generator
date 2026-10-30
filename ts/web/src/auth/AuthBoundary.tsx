'use client';

import { useEffect, useState, type ReactNode } from 'react';
import { completeAuthorizationCodeFlow } from './session';

export default function AuthBoundary({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const complete = async (): Promise<void> => {
      try {
        const exchanged = await completeAuthorizationCodeFlow();
        if (exchanged) {
          window.location.replace('/');
          return;
        }
        if (!cancelled) setReady(true);
      } catch {
        window.history.replaceState(null, '', '/auth/callback');
        if (!cancelled) setFailed(true);
      }
    };
    void complete();
    return () => {
      cancelled = true;
    };
  }, []);

  if (failed) {
    return (
      <main>
        <h1>Sign in again</h1>
        <p>This sign-in attempt expired or could not be completed.</p>
        <a href="/auth/login">Sign in to ThreatForest</a>
      </main>
    );
  }
  return ready ? children : <div suppressHydrationWarning />;
}
