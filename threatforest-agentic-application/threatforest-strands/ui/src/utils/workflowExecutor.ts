import { PythonBridge } from './pythonBridge';

export interface WorkflowConfig {
  projectPath: string;
  threatModelPath?: string;
  awsProfile?: string;
  bedrockModel: string;
  enableCache: boolean;
}

export interface WorkflowProgress {
  stage: string;
  current: number;
  total: number;
  message?: string;
  parallelTasks?: ParallelTask[];
}

export interface ParallelTask {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  progress?: number;
}

export type ProgressCallback = (progress: WorkflowProgress) => void;

export class WorkflowExecutor {
  private bridge: PythonBridge;
  private config: WorkflowConfig;
  private onProgress?: ProgressCallback;
  private startTime: number = Date.now();

  constructor(config: WorkflowConfig, onProgress?: ProgressCallback) {
    this.bridge = new PythonBridge();
    this.config = config;
    this.onProgress = onProgress;
  }

  private updateProgress(stage: string, current: number, total: number, message?: string, parallelTasks?: ParallelTask[]) {
    if (this.onProgress) {
      this.onProgress({ stage, current, total, message, parallelTasks });
    }
  }

  async executeWorkflow() {
    this.startTime = Date.now();
    
    try {
      // Use Strands orchestrator for full workflow execution
      this.updateProgress('setup', 0, 5, 'Initializing workflow...');
      
      const result = await this.bridge.runOrchestratedWorkflow({
        project_path: this.config.projectPath,
        threat_model_path: this.config.threatModelPath,
        aws_profile: this.config.awsProfile,
        bedrock_model: this.config.bedrockModel,
        resume: false
      }, (event) => {
        // Map progress event to UI update
        const stageMap: Record<string, string> = {
          'setup': 'setup',
          'context_analysis': 'context',
          'extraction': 'extraction',
          'tree_generation': 'trees',
          'summary': 'summary',
          'complete': 'complete'
        };
        
        const stage = stageMap[event.stage] || 'processing';
        const current = Math.floor(event.percentage / 20);
        
        // Build parallel tasks for threat-level progress
        const parallelTasks = event.details?.threat_id ? [{
          id: event.details.threat_id,
          name: event.message,
          status: event.type === 'threat_complete' ? 'complete' : 
                 event.type === 'error' ? 'error' : 'running',
          progress: event.percentage
        }] : undefined;
        
        this.updateProgress(stage, current, 5, event.message, parallelTasks);
      });
      
      if (!result.success) {
        throw new Error(result.error);
      }
      
      const data = result.data;
      
      // Update progress based on orchestrator result
      if (data.status === 'setup_failed') {
        throw new Error(data.message || 'Setup validation failed');
      }
      
      // Extract results from orchestrator context
      const context = data.context || {};
      const extractionData = context.extracted_info || {};
      const treesData = context.attack_trees || {};
      const summaryData = context.summary || {};
      
      // Complete
      this.updateProgress('complete', 5, 5, 'Workflow complete');
      
      return {
        success: true,
        data: {
          context: context.context_files,
          extraction: extractionData,
          trees: treesData,
          summary: summaryData,
          outputDir: data.output_directory,
          threatsProcessed: extractionData.extraction_summary?.high_severity_count || 0,
          attackTrees: treesData.generation_summary?.successful_generations || 0,
          duration: Date.now() - this.startTime
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async validateConfiguration(): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    const validation = await this.bridge.validateInput('setup', {
      project_path: this.config.projectPath,
      aws_profile: this.config.awsProfile,
      bedrock_model: this.config.bedrockModel
    });

    if (!validation.success) {
      errors.push(validation.error || 'Invalid configuration');
    }

    return { valid: errors.length === 0, errors };
  }

  async checkForResume(): Promise<{ canResume: boolean; state?: any }> {
    const result = await this.bridge.loadState(this.config.projectPath);
    return {
      canResume: result.success && result.data !== null,
      state: result.data
    };
  }

  getStartTime(): number {
    return this.startTime;
  }
}
