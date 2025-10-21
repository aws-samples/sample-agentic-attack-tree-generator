import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { WelcomeScreen } from './WelcomeScreen';
import { ConfigurationScreen } from './ConfigurationScreen';
import { ProgressScreen } from './ProgressScreen';
import { SummaryScreen } from './SummaryScreen';
import { ErrorDisplay } from './ErrorDisplay';
import { PathSelector } from './PathSelector';
import { ContinuePrompt } from './ContinuePrompt';
import { useWorkflow } from '../hooks/useWorkflow';

export type Screen = 'welcome' | 'config' | 'pathSelect' | 'progress' | 'summary' | 'error' | 'continue' | 'continueToMitigate';
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
  const [simpleError, setSimpleError] = useState<string>('');
  const { state: workflowState, executeWorkflow, clearError, updateState } = useWorkflow();

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
        setScreen('continue');
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
      const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
      updateState({
        stage: mode === 'enrich' ? 'trees' : 'summary',
        current,
        total,
        message,
        percentage
      });
    };
    
    try {
      if (mode === 'enrich') {
        updateState({ 
          stage: 'trees', 
          message: '🎯 Starting TTC enrichment...', 
          current: 0, 
          total: 0,
          data: { mode: 'enrich' }
        });
        
        const result = await bridge.enrichAttackTrees(finalInputDir, finalOutputDir, handleProgress);
        
        if (result.success) {
          updateState({ 
            stage: 'complete',
            message: `✅ Enriched ${result.data.enriched_count} attack trees`,
            data: {
              mode: 'enrich',
              attackTrees: result.data.enriched_count,
              threatsProcessed: result.data.enriched_count,
              outputDir: result.data.output_dir
            }
          });
          setTimeout(() => setScreen('summary'), 1000);
        } else {
          throw new Error(result.error);
        }
      } else if (mode === 'mitigate') {
        updateState({ 
          stage: 'summary', 
          message: '🛡️ Starting mitigation mapping...', 
          current: 0, 
          total: 0,
          data: { mode: 'mitigate' }
        });
        
        const result = await bridge.addMitigations(finalInputDir, finalOutputDir, handleProgress);
        
        if (result.success) {
          updateState({ 
            stage: 'complete',
            message: `✅ Added mitigations to ${result.data.processed_count} files`,
            data: {
              mode: 'mitigate',
              attackTrees: result.data.processed_count,
              threatsProcessed: result.data.techniques_with_mitigations || result.data.processed_count,
              totalMitigations: result.data.total_mitigations || 0,
              outputDir: result.data.output_dir
            }
          });
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

  const handleContinue = async (shouldContinue: boolean) => {
    if (!shouldContinue) {
      setScreen('summary');
      return;
    }

    const { PythonBridge } = await import('../utils/pythonBridge');
    const bridge = new PythonBridge();
    
    // Use the output directory from Option 1's completed workflow
    const attackTreesDir = workflowState.data?.outputDir || `${appState.projectPath}/threatforest/attack_trees`;
    const enrichedDir = `${appState.projectPath}/threatforest/enriched`;
    
    const handleProgress = (current: number, total: number, message: string) => {
      const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
      updateState({
        stage: 'trees',
        current,
        total,
        message,
        percentage
      });
    };
    
    try {
      setScreen('progress');
      
      updateState({ 
        stage: 'trees', 
        message: '🎯 Starting TTC enrichment...', 
        current: 0, 
        total: 0,
        data: { mode: 'enrich' }
      });
      
      const enrichResult = await bridge.enrichAttackTrees(attackTreesDir, enrichedDir, handleProgress);
      
      if (!enrichResult.success) {
        throw new Error(enrichResult.error);
      }
      
      updateState({ 
        stage: 'complete',
        message: `✅ Enriched ${enrichResult.data.enriched_count} attack trees`,
        data: {
          mode: 'enrich',
          attackTrees: enrichResult.data.enriched_count,
          threatsProcessed: enrichResult.data.enriched_count,
          outputDir: enrichResult.data.output_dir
        }
      });
      
      setScreen('continueToMitigate');
    } catch (error) {
      setSimpleError(error instanceof Error ? error.message : 'Unknown error');
      setScreen('error');
    }
  };

  const handleContinueToMitigate = async (shouldContinue: boolean) => {
    if (!shouldContinue) {
      setScreen('summary');
      return;
    }

    const { PythonBridge } = await import('../utils/pythonBridge');
    const bridge = new PythonBridge();
    
    // Use the output directory from Option 2's completed workflow
    const enrichedDir = workflowState.data?.outputDir || `${appState.projectPath}/threatforest/enriched`;
    const mitigatedDir = `${appState.projectPath}/threatforest/mitigated`;
    
    const handleProgress = (current: number, total: number, message: string) => {
      const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
      updateState({
        stage: 'summary',
        current,
        total,
        message,
        percentage
      });
    };
    
    try {
      setScreen('progress');
      
      updateState({ 
        stage: 'summary', 
        message: '🛡️ Starting mitigation mapping...', 
        current: 0, 
        total: 0,
        data: { mode: 'mitigate' }
      });
      
      const mitigateResult = await bridge.addMitigations(enrichedDir, mitigatedDir, handleProgress);
      
      if (mitigateResult.success) {
        updateState({ 
          stage: 'complete',
          message: `✅ Complete workflow finished`,
          data: {
            mode: 'full',
            attackTrees: mitigateResult.data.processed_count,
            threatsProcessed: mitigateResult.data.techniques_with_mitigations || mitigateResult.data.processed_count,
            totalMitigations: mitigateResult.data.total_mitigations || 0,
            outputDir: mitigatedDir
          }
        });
        setTimeout(() => setScreen('summary'), 1000);
      } else {
        throw new Error(mitigateResult.error);
      }
    } catch (error) {
      setSimpleError(error instanceof Error ? error.message : 'Unknown error');
      setScreen('error');
    }
  };

  return (
    <Box flexDirection="column" padding={1}>
      {screen === 'welcome' && <WelcomeScreen onNext={handleNext} />}
      {screen === 'pathSelect' && appState.mode && (appState.mode === 'enrich' || appState.mode === 'mitigate') && (
        <PathSelector mode={appState.mode} onSubmit={handlePathSubmit} />
      )}
      {screen === 'config' && <ConfigurationScreen onNext={handleNext} state={appState} />}
      {screen === 'continue' && (
        <ContinuePrompt 
          message="Option 1 complete! Continue with TTC Enrichment (Option 2)?"
          onContinue={() => handleContinue(true)}
          onSkip={() => handleContinue(false)}
        />
      )}
      {screen === 'continueToMitigate' && (
        <ContinuePrompt 
          message="Option 2 complete! Continue with Mitigation Mapping (Option 3)?"
          onContinue={() => handleContinueToMitigate(true)}
          onSkip={() => handleContinueToMitigate(false)}
        />
      )}
      {screen === 'progress' && <ProgressScreen state={workflowState} />}
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
