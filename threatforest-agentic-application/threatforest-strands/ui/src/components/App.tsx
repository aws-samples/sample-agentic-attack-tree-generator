import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { WelcomeScreen } from './WelcomeScreen';
import { ConfigurationScreen } from './ConfigurationScreen';
import { ProgressScreen } from './ProgressScreen';
import { SummaryScreen } from './SummaryScreen';
import { ErrorDisplay } from './ErrorDisplay';
import { PathSelector } from './PathSelector';
import { useWorkflow } from '../hooks/useWorkflow';

export type Screen = 'welcome' | 'config' | 'pathSelect' | 'progress' | 'summary' | 'error';
export type Mode = 'full' | 'enrich' | 'mitigate';

export interface AppState {
  mode?: Mode;
  projectPath?: string;
  awsProfile?: string;
  bedrockModel?: string;
  enableCache?: boolean;
  inputDir?: string;
  outputDir?: string;
}

export const App: React.FC = () => {
  const [screen, setScreen] = useState<Screen>('welcome');
  const [appState, setAppState] = useState<AppState>({});
  const [simpleProgress, setSimpleProgress] = useState<string>('');
  const [progressCurrent, setProgressCurrent] = useState<number>(0);
  const [progressTotal, setProgressTotal] = useState<number>(0);
  const [simpleError, setSimpleError] = useState<string>('');
  const { state: workflowState, executeWorkflow, clearError } = useWorkflow();

  const handleNext = async (newState: Partial<AppState>) => {
    const updatedState = { ...appState, ...newState };
    setAppState(updatedState);
    
    if (screen === 'welcome') {
      const mode = newState.mode || 'full';
      
      // For enrich/mitigate modes, go to path selection
      if (mode === 'enrich' || mode === 'mitigate') {
        setScreen('pathSelect');
      } else {
        setScreen('config');
      }
    } else if (screen === 'config') {
      setScreen('progress');
      
      // Execute workflow
      const config = {
        projectPath: newState.projectPath || appState.projectPath || '',
        awsProfile: newState.awsProfile || appState.awsProfile,
        bedrockModel: newState.bedrockModel || appState.bedrockModel || '',
        enableCache: newState.enableCache ?? appState.enableCache ?? true
      };
      
      const result = await executeWorkflow(config);
      
      if (result.success) {
        setScreen('summary');
      } else {
        setScreen('error');
      }
    }
  };

  const handlePathSubmit = async (inputDir: string, outputDir: string) => {
    setAppState({ ...appState, inputDir, outputDir });
    setScreen('progress');
    await executeEnrichmentOrMitigation(appState.mode!, inputDir, outputDir);
  };

  const executeEnrichmentOrMitigation = async (mode: Mode, inputDir: string, outputDir: string) => {
    const { PythonBridge } = await import('../utils/pythonBridge');
    const bridge = new PythonBridge();
    
    // Use defaults if empty
    const finalInputDir = inputDir || (mode === 'enrich' 
      ? `${process.cwd()}/../output/attack_trees`
      : `${process.cwd()}/../output/enriched`);
    
    const finalOutputDir = outputDir || (mode === 'enrich'
      ? `${process.cwd()}/../output/enriched`
      : `${process.cwd()}/../output/mitigated`);
    
    const handleProgress = (current: number, total: number, message: string) => {
      setProgressCurrent(current);
      setProgressTotal(total);
      setSimpleProgress(message);
    };
    
    try {
      if (mode === 'enrich') {
        setSimpleProgress('🎯 Starting TTC enrichment...');
        
        const result = await bridge.enrichAttackTrees(finalInputDir, finalOutputDir, handleProgress);
        
        if (result.success) {
          setSimpleProgress(`✅ Enriched ${result.data.enriched_count} attack trees`);
          setTimeout(() => setScreen('summary'), 1000);
        } else {
          throw new Error(result.error);
        }
      } else if (mode === 'mitigate') {
        setSimpleProgress('🛡️ Starting mitigation mapping...');
        
        const result = await bridge.addMitigations(finalInputDir, finalOutputDir, handleProgress);
        
        if (result.success) {
          setSimpleProgress(`✅ Added mitigations to ${result.data.processed_count} files`);
          setTimeout(() => setScreen('summary'), 1000);
        } else {
          throw new Error(result.error);
        }
      }
    } catch (error) {
      setSimpleError(error instanceof Error ? error.message : 'Unknown error');
      setScreen('error');
    }
  };

  const handleRetry = () => {
    clearError();
    setScreen('config');
  };

  return (
    <Box flexDirection="column" padding={1}>
      {screen === 'welcome' && <WelcomeScreen onNext={handleNext} />}
      {screen === 'pathSelect' && appState.mode && (appState.mode === 'enrich' || appState.mode === 'mitigate') && (
        <PathSelector mode={appState.mode} onSubmit={handlePathSubmit} />
      )}
      {screen === 'config' && <ConfigurationScreen onNext={handleNext} state={appState} />}
      {screen === 'progress' && (
        appState.mode === 'enrich' || appState.mode === 'mitigate' ? (
          <Box flexDirection="column" borderStyle="round" borderColor="cyan" padding={1}>
            <Text bold color="cyan">
              {appState.mode === 'enrich' ? '🎯 TTC Enrichment' : '🛡️ Mitigation Mapping'}
            </Text>
            <Box marginTop={1}>
              <Text>{simpleProgress}</Text>
            </Box>
            {progressTotal > 0 && (
              <Box marginTop={1}>
                <Text>
                  Progress: {progressCurrent}/{progressTotal} ({Math.round((progressCurrent / progressTotal) * 100)}%)
                </Text>
              </Box>
            )}
          </Box>
        ) : (
          <ProgressScreen state={workflowState} />
        )
      )}
      {screen === 'summary' && <SummaryScreen state={workflowState} />}
      {screen === 'error' && (simpleError || workflowState.error) && (
        <ErrorDisplay 
          error={simpleError || workflowState.error || 'Unknown error'} 
          onRetry={handleRetry}
          onAbort={() => process.exit(1)}
        />
      )}
    </Box>
  );
};
