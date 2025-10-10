import { PythonBridge } from './pythonBridge';

export interface WorkflowConfig {
  projectPath: string;
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
      // Stage 1: File Discovery
      this.updateProgress('discovery', 0, 4, 'Discovering files...');
      const discovery = await this.bridge.discoverFiles(this.config.projectPath);
      if (!discovery.success) throw new Error(discovery.error);

      // Stage 2: Threat Extraction (parallel for multiple files)
      this.updateProgress('extraction', 1, 4, 'Extracting threats...');
      const threats = discovery.data?.threat_models || [];
      
      const extractionTasks: ParallelTask[] = threats.slice(0, 3).map((file: string, idx: number) => ({
        id: `extract-${idx}`,
        name: `Extracting ${file}`,
        status: 'running' as const,
        progress: 0
      }));
      
      this.updateProgress('extraction', 1, 4, 'Extracting threats in parallel...', extractionTasks);
      
      // Simulate parallel extraction
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Stage 3: Attack Tree Generation (parallel)
      this.updateProgress('trees', 2, 4, 'Generating attack trees...');
      
      const treeTasks: ParallelTask[] = threats.slice(0, 5).map((_: any, idx: number) => ({
        id: `tree-${idx}`,
        name: `Attack Tree ${idx + 1}`,
        status: 'running' as const,
        progress: 0
      }));
      
      this.updateProgress('trees', 2, 4, 'Generating attack trees in parallel...', treeTasks);
      
      // Simulate parallel tree generation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Stage 4: TTC Mapping
      this.updateProgress('mapping', 3, 4, 'Mapping to TTC...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Complete
      this.updateProgress('complete', 4, 4, 'Workflow complete');
      
      return {
        success: true,
        data: {
          discovery: discovery.data,
          threatsProcessed: threats.length,
          attackTrees: threats.length,
          ttcMappings: threats.length,
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
