import { spawn } from 'child_process';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface PythonResult {
  success: boolean;
  data?: any;
  error?: string;
}

export class PythonBridge {
  private pythonPath: string;
  private projectRoot: string;

  constructor() {
    // Since the CLI runs from ui/ directory (cwd=ui_dir in threatforest.py),
    // we need to go up one level to get to project root
    this.projectRoot = path.join(process.cwd(), '..');
    this.pythonPath = process.env.PYTHON_PATH || 'python';
  }

  async execute(module: string, className: string, method: string, args: any = {}): Promise<PythonResult> {
    return new Promise((resolve) => {
      const argsJson = JSON.stringify(args).replace(/'/g, "\\'");
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from ${module} import ${className}

try:
    args = json.loads('${argsJson}')
    instance = ${className}(**args.get('init', {}))
    result = getattr(instance, '${method}')(**args.get('call', {}))
    
    # Convert to serializable format
    if hasattr(result, '__dict__'):
        result = result.__dict__
    elif hasattr(result, '_asdict'):
        result = result._asdict()
    
    print(json.dumps({'success': True, 'data': result}))
except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => output += data.toString());
      python.stderr.on('data', (data) => error += data.toString());

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

  // FileDiscovery integration
  async discoverFiles(projectPath: string): Promise<PythonResult> {
    return this.execute(
      'src.modules.core.file_discovery',
      'FileDiscovery',
      'discover_all',
      { init: { project_path: projectPath }, call: {} }
    );
  }

  // Cache integration
  async getCacheStats(): Promise<PythonResult> {
    return this.execute(
      'src.modules.core.cache',
      'BedrockResponseCache',
      'get_stats',
      { init: {}, call: {} }
    );
  }

  async clearCache(): Promise<PythonResult> {
    return this.execute(
      'src.modules.core.cache',
      'BedrockResponseCache',
      'clear',
      { init: {}, call: {} }
    );
  }

  // StateManager integration
  async loadState(projectPath?: string): Promise<PythonResult> {
    return this.execute(
      'src.modules.core.state_manager',
      'StateManager',
      'load_checkpoint',
      { init: { project_path: projectPath }, call: {} }
    );
  }

  async saveState(state: any, projectPath?: string): Promise<PythonResult> {
    return this.execute(
      'src.modules.core.state_manager',
      'StateManager',
      'save_checkpoint',
      { init: { project_path: projectPath }, call: { state } }
    );
  }

  // Validation integration
  async validateInput(inputType: string, data: any): Promise<PythonResult> {
    const classMap: Record<string, string> = {
      setup: 'SetupToolInput',
      context: 'ContextAnalysisInput',
      extraction: 'ExtractionToolInput',
      attacktree: 'AttackTreeGeneratorInput'
    };

    const className = classMap[inputType];
    if (!className) {
      return { success: false, error: `Unknown input type: ${inputType}` };
    }

    return this.execute(
      'src.modules.core.validation',
      className,
      'validate',
      { init: data, call: {} }
    );
  }

  // Parser integration
  async parseThreats(content: string, filePath: string): Promise<PythonResult> {
    return this.execute(
      'src.modules.parsers.chain',
      'ParserChain',
      'parse',
      { init: {}, call: { content, file_path: filePath } }
    );
  }
}
