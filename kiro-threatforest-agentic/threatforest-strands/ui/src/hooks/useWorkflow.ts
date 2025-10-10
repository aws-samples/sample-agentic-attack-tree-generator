import { useState, useCallback } from 'react';
import { PythonBridge } from '../utils/pythonBridge';

export type WorkflowStage = 
  | 'setup'
  | 'discovery'
  | 'extraction'
  | 'trees'
  | 'mapping'
  | 'summary';

export interface WorkflowState {
  stage: WorkflowStage;
  progress: { current: number; total: number };
  error?: string;
  data?: any;
}

export const useWorkflow = () => {
  const [state, setState] = useState<WorkflowState>({
    stage: 'setup',
    progress: { current: 0, total: 0 }
  });

  const bridge = new PythonBridge();

  const runDiscovery = useCallback(async (projectPath: string) => {
    setState(prev => ({ ...prev, stage: 'discovery' }));
    const result = await bridge.discoverFiles(projectPath);
    
    if (result.success) {
      setState(prev => ({ 
        ...prev, 
        data: { ...prev.data, discovery: result.data }
      }));
      return result.data;
    } else {
      setState(prev => ({ ...prev, error: result.error }));
      return null;
    }
  }, []);

  const nextStage = useCallback(() => {
    const stages: WorkflowStage[] = ['setup', 'discovery', 'extraction', 'trees', 'mapping', 'summary'];
    const currentIndex = stages.indexOf(state.stage);
    if (currentIndex < stages.length - 1) {
      setState(prev => ({ ...prev, stage: stages[currentIndex + 1] }));
    }
  }, [state.stage]);

  const updateProgress = useCallback((current: number, total: number) => {
    setState(prev => ({ ...prev, progress: { current, total } }));
  }, []);

  return {
    state,
    runDiscovery,
    nextStage,
    updateProgress
  };
};
