import { spawn } from 'child_process';
import * as path from 'path';

export interface PythonResult {
  success: boolean;
  data?: any;
  error?: string;
}

export class PythonBridge {
  private pythonPath: string;
  private projectRoot: string;

  constructor() {
    this.projectRoot = path.join(__dirname, '../../..');
    this.pythonPath = process.env.PYTHON_PATH || 'python';
  }

  async execute(module: string, method: string, args: any = {}): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from ${module} import ${method.split('.')[0]}

try:
    args = json.loads('${JSON.stringify(args)}')
    result = ${method}(**args)
    print(json.dumps({'success': True, 'data': result}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => {
        output += data.toString();
      });

      python.stderr.on('data', (data) => {
        error += data.toString();
      });

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Python process failed' });
        } else {
          try {
            const result = JSON.parse(output);
            resolve(result);
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse Python output' });
          }
        }
      });
    });
  }

  async getCacheStats(): Promise<any> {
    return this.execute('threatforest.core.cache', 'BedrockResponseCache().get_stats');
  }

  async discoverFiles(projectPath: string): Promise<any> {
    return this.execute('threatforest.core.file_discovery', 'FileDiscovery', { project_path: projectPath });
  }

  async loadState(): Promise<any> {
    return this.execute('threatforest.core.state_manager', 'StateManager.load_checkpoint');
  }
}
