import { useState, useCallback } from 'react';
import { WorkflowExecutor, WorkflowConfig, WorkflowProgress, ParallelTask } from '../utils/workflowExecutor';

export type WorkflowStage = 
  | 'setup'
  | 'discovery'
  | 'extraction'
  | 'trees'
  | 'mapping'
  | 'complete';

export interface WorkflowState {
  stage: WorkflowStage;
  progress: { current: number; total: number };
  current?: number;
  total?: number;
  percentage?: number;
  error?: string;
  data?: any;
  message?: string;
  parallelTasks?: ParallelTask[];
  startTime?: number;
}

export const useWorkflow = (config?: WorkflowConfig) => {
  const [state, setState] = useState<WorkflowState>({
    stage: 'setup',
    progress: { current: 0, total: 0 }
  });

  const handleProgress = useCallback((progress: WorkflowProgress) => {
    setState(prev => ({
      ...prev,
      stage: progress.stage as WorkflowStage,
      progress: { current: progress.current, total: progress.total },
      message: progress.message,
      parallelTasks: progress.parallelTasks
    }));
  }, []);

  const executeWorkflow = useCallback(async (workflowConfig: WorkflowConfig) => {
    const executor = new WorkflowExecutor(workflowConfig, handleProgress);
    
    // Set start time
    setState(prev => ({ ...prev, startTime: executor.getStartTime() }));
    
    // Validate configuration
    const validation = await executor.validateConfiguration();
    if (!validation.valid) {
      setState(prev => ({ 
        ...prev, 
        error: validation.errors.join(', ') 
      }));
      return { success: false, error: validation.errors.join(', ') };
    }

    // Execute workflow
    const result = await executor.executeWorkflow();
    
    if (result.success) {
      setState(prev => ({ 
        ...prev, 
        stage: 'complete',
        data: result.data 
      }));
    } else {
      setState(prev => ({ 
        ...prev, 
        error: result.error 
      }));
    }

    return result;
  }, [handleProgress]);

  const checkResume = useCallback(async (projectPath: string) => {
    const executor = new WorkflowExecutor({ 
      projectPath, 
      bedrockModel: '', 
      enableCache: true 
    });
    return executor.checkForResume();
  }, []);

  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: undefined }));
  }, []);

  const updateState = useCallback((updates: Partial<WorkflowState>) => {
    setState(prev => ({
      ...prev,
      ...updates,
      progress: updates.current !== undefined && updates.total !== undefined
        ? { current: updates.current, total: updates.total }
        : prev.progress
    }));
  }, []);

  return {
    state,
    executeWorkflow,
    checkResume,
    clearError,
    updateState
  };
};
