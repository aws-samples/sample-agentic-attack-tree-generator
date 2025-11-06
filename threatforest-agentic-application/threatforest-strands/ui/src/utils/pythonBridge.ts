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

export interface ProgressEvent {
  type: string;
  timestamp: string;
  stage: string;
  percentage: number;
  message: string;
  details?: any;
}

export class PythonBridge {
  private pythonPath: string;
  private projectRoot: string;
  private logFilePath: string | null = null;

  constructor() {
    // Since the CLI runs from ui/ directory (cwd=ui_dir in threatforest.py),
    // we need to go up one level to get to project root
    this.projectRoot = path.resolve(process.cwd(), '..');
    this.pythonPath = process.env.PYTHON_PATH || 'python';
    
    // Create absolute log file path once for all subprocesses
    const now = new Date();
    const timestamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`;
    this.logFilePath = path.resolve(this.projectRoot, 'output', 'logs', `threatforest_run_${timestamp}.log`);
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

  // TTC Enrichment
  async enrichAttackTrees(inputDir: string, outputDir: string, onProgress?: (current: number, total: number, message: string) => void): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

try:
    embeddings_path = Path('${this.projectRoot}') / 'src' / 'modules' / 'ttc_mappings' / 'data' / 'ttc_embeddings.json'
    
    if not embeddings_path.exists():
        raise FileNotFoundError(f"Embeddings not found: {embeddings_path}")
    
    print(json.dumps({'type': 'progress', 'current': 0, 'total': 0, 'message': 'Loading TTC matcher...'}), flush=True)
    
    matcher = TTCMatcher(embeddings_path=str(embeddings_path), min_similarity=0.35)
    enricher = AttackTreeEnricher(matcher)
    
    input_path = Path('${inputDir}')
    output_path = Path('${outputDir}')
    output_path.mkdir(parents=True, exist_ok=True)
    
    files = list(input_path.glob('attack_tree_*.md'))
    total = len(files)
    enriched = 0
    
    print(json.dumps({'type': 'progress', 'current': 0, 'total': total, 'message': f'Found {total} attack trees to enrich'}), flush=True)
    
    for i, file in enumerate(files, 1):
        print(json.dumps({'type': 'progress', 'current': i, 'total': total, 'message': f'Enriching {file.name}...'}), flush=True)
        output_file = output_path / f"enriched_{file.name}"
        enricher.enrich_file(str(file), str(output_file))
        enriched += 1
    
    print(json.dumps({
        'success': True, 
        'data': {
            'enriched_count': enriched,
            'output_dir': str(output_path)
        }
    }))
except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          
          try {
            const parsed = JSON.parse(line);
            if (parsed.type === 'progress' && onProgress) {
              onProgress(parsed.current, parsed.total, parsed.message);
            } else if (parsed.success !== undefined) {
              output = line;
            }
          } catch (e) {
            // Not JSON, accumulate as output
            output += line;
          }
        }
      });
      
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Enrichment failed' });
        } else {
          try {
            const result = JSON.parse(output);
            resolve(result);
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse output' });
          }
        }
      });
    });
  }

  // Mitigation Mapping
  async addMitigations(inputDir: string, outputDir: string, onProgress?: (current: number, total: number, message: string) => void): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.modules.ttc_mappings.mitigation_mapper import MitigationMapper
from src.config import config

try:
    bundle_path = config.stix_bundle_path
    
    if not bundle_path.exists():
        raise FileNotFoundError(f"STIX bundle not found: {bundle_path}")
    
    print(json.dumps({'type': 'progress', 'current': 0, 'total': 0, 'message': 'Loading mitigation mapper...'}), flush=True)
    
    mapper = MitigationMapper(str(bundle_path))
    
    input_path = Path('${inputDir}')
    output_path = Path('${outputDir}')
    output_path.mkdir(parents=True, exist_ok=True)
    
    files = list(input_path.glob('*.md'))
    total = len(files)
    processed = 0
    techniques_with_mitigations = 0
    total_mitigations = 0
    
    print(json.dumps({'type': 'progress', 'current': 0, 'total': total, 'message': f'Found {total} files to process'}), flush=True)
    
    for i, file in enumerate(files, 1):
        print(json.dumps({'type': 'progress', 'current': i, 'total': total, 'message': f'Processing {file.name}...'}), flush=True)
        output_file = output_path / f"mitigated_{file.name}"
        result = mapper.process_enriched_file(str(file), str(output_file))
        
        if result['mitigations_found']:
            techniques_with_mitigations += len(result['techniques'])
            for tech in result['techniques']:
                total_mitigations += len(tech.get('mitigations', []))
        
        processed += 1
    
    print(json.dumps({
        'success': True,
        'data': {
            'processed_count': processed,
            'techniques_with_mitigations': techniques_with_mitigations,
            'total_mitigations': total_mitigations,
            'output_dir': str(output_path)
        }
    }))
except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          
          try {
            const parsed = JSON.parse(line);
            if (parsed.type === 'progress' && onProgress) {
              onProgress(parsed.current, parsed.total, parsed.message);
            } else if (parsed.success !== undefined) {
              output = line;
            }
          } catch (e) {
            // Not JSON, accumulate as output
            output += line;
          }
        }
      });
      
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Mitigation mapping failed' });
        } else {
          try {
            const result = JSON.parse(output);
            resolve(result);
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse output' });
          }
        }
      });
    });
  }

  // FileDiscovery integration
  async discoverFiles(projectPath: string): Promise<PythonResult> {
    // FileDiscovery.discover() is a static method, not an instance method
    return new Promise((resolve) => {
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from src.modules.core.file_discovery import FileDiscovery

try:
    result = FileDiscovery.discover('${projectPath}')
    
    # Convert dataclass to dict
    if hasattr(result, '__dict__'):
        data = result.__dict__
    else:
        data = {
            'threat_models': result.threat_models,
            'source_code': result.source_code,
            'config_files': result.config_files,
            'documentation': result.documentation,
            'diagrams': result.diagrams,
            'all_files': result.all_files,
            'total_files': result.total_files,
            'total_size_bytes': result.total_size_bytes,
            'discovery_time_ms': result.discovery_time_ms,
            'excluded_dirs': result.excluded_dirs
        }
    
    print(json.dumps({'success': True, 'data': data}))
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


  // StateManager integration
  async loadState(projectPath?: string): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from src.modules.core.state_manager import StateManager

try:
    manager = StateManager()
    state = manager.load_checkpoint('latest')
    
    if state is None:
        print(json.dumps({'success': False, 'error': 'No checkpoint found'}))
    else:
        # Use Pydantic v2's model_dump() method
        data = state.model_dump()
        print(json.dumps({'success': True, 'data': data}))
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

  async saveState(state: any, projectPath?: string): Promise<PythonResult> {
    return new Promise((resolve) => {
      const stateJson = JSON.stringify(state).replace(/'/g, "\\'");
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from src.modules.core.state_manager import StateManager
from src.modules.core.state import ThreatForestState

try:
    manager = StateManager()
    state_data = json.loads('${stateJson}')
    
    # Create ThreatForestState instance (Pydantic v2 validates during __init__)
    state = ThreatForestState(**state_data)
    
    # Save checkpoint
    manager.save_checkpoint(state, 'latest')
    
    print(json.dumps({'success': True, 'data': {'message': 'State saved successfully'}}))
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

    // For Pydantic v2, validation happens during __init__
    // Just try to create the instance - if it succeeds, validation passed
    return new Promise((resolve) => {
      const argsJson = JSON.stringify(data).replace(/'/g, "\\'");
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

from src.modules.core.validation import ${className}

try:
    args = json.loads('${argsJson}')
    # Validation happens here - if this succeeds, input is valid
    instance = ${className}(**args)
    print(json.dumps({'success': True, 'data': instance.model_dump()}))
except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      python.stderr.on('data', (data: Buffer) => {
        error += data.toString();
      });

      python.on('close', (code: number) => {
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

  async getAwsProfiles(): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
import configparser
from pathlib import Path

try:
    profiles = set()
    
    # Read from credentials file
    credentials_path = Path.home() / '.aws' / 'credentials'
    if credentials_path.exists():
        config = configparser.ConfigParser()
        config.read(credentials_path)
        profiles.update(config.sections())
    
    # Read from config file (profiles are prefixed with 'profile ')
    config_path = Path.home() / '.aws' / 'config'
    if config_path.exists():
        config = configparser.ConfigParser()
        config.read(config_path)
        for section in config.sections():
            if section.startswith('profile '):
                profiles.add(section.replace('profile ', '', 1))
            elif section == 'default':
                profiles.add('default')
    
    if not profiles:
        profiles = {'default'}
    
    print(json.dumps({'success': True, 'data': sorted(list(profiles))}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
`;

      const python = spawn('python3', ['-c', script]);
      let output = '';

      python.stdout.on('data', (data) => {
        output += data.toString();
      });

      python.on('close', () => {
        const lines = output.trim().split('\n');
        const lastLine = lines[lines.length - 1];
        if (lastLine) {
          try {
            resolve(JSON.parse(lastLine));
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse Python output' });
          }
        }
      });
    });
  }

  async validateAwsCredentials(awsProfile?: string): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
sys.path.insert(0, '${this.projectRoot}')

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    session = boto3.Session(profile_name='${awsProfile || 'default'}')
    
    # Validate credentials
    sts = session.client('sts')
    identity = sts.get_caller_identity()
    
    # Validate Bedrock access
    bedrock = session.client('bedrock', region_name='us-east-1')
    
    try:
        # List foundation models to verify Bedrock access
        response = bedrock.list_foundation_models()
        models = response.get('modelSummaries', [])
        
        # Filter for available models with on-demand throughput support
        available_models = [
            {
                'modelId': m['modelId'],
                'modelName': m.get('modelName', m['modelId']),
                'provider': m.get('providerName', 'Unknown')
            }
            for m in models
            if m.get('modelLifecycle', {}).get('status') == 'ACTIVE'
            and 'ON_DEMAND' in m.get('inferenceTypesSupported', [])
        ]
        
        # Also fetch inference profiles (for Claude 4/4.5)
        try:
            profiles_response = bedrock.list_inference_profiles()
            profiles = profiles_response.get('inferenceProfileSummaries', [])
            for p in profiles:
                if p.get('status') == 'ACTIVE':
                    available_models.append({
                        'modelId': p['inferenceProfileArn'],
                        'modelName': p.get('inferenceProfileName', p['inferenceProfileId']),
                        'provider': 'Anthropic'  # Most profiles are Claude
                    })
        except Exception:
            pass  # Inference profiles optional
        
        print(json.dumps({
            'success': True, 
            'data': {
                'account': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId'],
                'bedrock_access': True,
                'available_models': available_models
            }
        }))
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            print(json.dumps({
                'success': False, 
                'error': 'AWS credentials valid but no Bedrock access. Grant bedrock:ListFoundationModels permission.'
            }))
        else:
            print(json.dumps({
                'success': False, 
                'error': f"Bedrock access check failed: {e.response['Error']['Message']}"
            }))
            
except NoCredentialsError:
    print(json.dumps({'success': False, 'error': 'No AWS credentials found'}))
except ClientError as e:
    print(json.dumps({'success': False, 'error': f"AWS credentials invalid: {e.response['Error']['Message']}"}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      python.stderr.on('data', (data: Buffer) => {
        error += data.toString();
      });

      python.on('close', (code: number) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Failed to validate credentials' });
        } else {
          try {
            const result = JSON.parse(output);
            resolve(result);
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse validation output' });
          }
        }
      });
    });
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

  // Workflow execution methods
  async runContextAnalysis(projectPath: string): Promise<PythonResult> {
    return new Promise((resolve) => {
      const script = `
import sys
import json
import asyncio
from pathlib import Path
import logging
sys.path.insert(0, '${this.projectRoot}')

from src.modules.utils.logger import ThreatForestLogger
from src.modules.tools.context_analysis_tool import ContextAnalysisTool

async def run():
    try:
        # Initialize logger with correct output directory BEFORE tool instantiation
        strands_root = Path('${this.projectRoot}')
        output_dir = strands_root / 'output'
        ThreatForestLogger.initialize(output_dir)
        
        tool = ContextAnalysisTool()
        result = await tool.execute('${projectPath}')
        print(json.dumps({'success': True, 'data': result}))
    except Exception as e:
        import traceback
        logging.error(f"Context analysis failed: {e}")
        logging.error(traceback.format_exc())
        print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))

asyncio.run(run())
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => output += data.toString());
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Context analysis failed' });
        } else {
          try {
            // Find last valid JSON line (in case of logs/warnings)
            const lines = output.trim().split('\n');
            let result = null;
            for (let i = lines.length - 1; i >= 0; i--) {
              try {
                result = JSON.parse(lines[i]);
                break;
              } catch (e) {
                continue;
              }
            }
            if (result) {
              resolve(result);
            } else {
              resolve({ success: false, error: 'No valid JSON output found' });
            }
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse context analysis output' });
          }
        }
      });
    });
  }

  async runInformationExtraction(params: {
    context_files: any;
    bedrock_model: string;
    aws_profile?: string;
    interactive: boolean;
  }): Promise<PythonResult> {
    return new Promise((resolve) => {
      const paramsJson = Buffer.from(JSON.stringify(params)).toString('base64');
      const script = `
import sys
import json
import asyncio
import base64
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.modules.tools.information_extraction_tool import InformationExtractionTool
from src.modules.utils.logger import ThreatForestLogger

async def run():
    try:
        # Initialize logger with correct output directory BEFORE tool instantiation
        strands_root = Path('${this.projectRoot}')
        output_dir = strands_root / 'output'
        ThreatForestLogger.initialize(output_dir)
        
        params = json.loads(base64.b64decode('${paramsJson}').decode('utf-8'))
        tool = InformationExtractionTool()
        result = await tool.execute(
            context_files=params['context_files'],
            bedrock_model=params['bedrock_model'],
            aws_profile=params.get('aws_profile'),
            interactive=params['interactive']
        )
        print(json.dumps({'success': True, 'data': result}))
    except Exception as e:
        import traceback
        logging.error(f"Information extraction failed: {e}")
        logging.error(traceback.format_exc())
        print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))

asyncio.run(run())
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => output += data.toString());
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Information extraction failed' });
        } else {
          try {
            const lines = output.trim().split('\n');
            let result = null;
            for (let i = lines.length - 1; i >= 0; i--) {
              try {
                result = JSON.parse(lines[i]);
                break;
              } catch (e) {
                continue;
              }
            }
            if (result) {
              resolve(result);
            } else {
              resolve({ success: false, error: 'No valid JSON output found' });
            }
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse extraction output' });
          }
        }
      });
    });
  }

  async runAttackTreeGeneration(params: {
    threat_statements: any[];
    extracted_info: any;
    bedrock_model: string;
    aws_profile?: string;
    output_dir?: string;
    project_path?: string;
  }): Promise<PythonResult> {
    return new Promise((resolve) => {
      const paramsJson = Buffer.from(JSON.stringify(params)).toString('base64');
      const script = `
import sys
import json
import asyncio
import base64
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.modules.tools.attack_tree_generator_tool import AttackTreeGeneratorTool
from src.modules.utils.logger import ThreatForestLogger

def save_attack_trees(trees_result, output_dir, project_path):
    """Save attack trees to disk"""
    if not trees_result or 'attack_trees' not in trees_result:
        return
    
    # Get project name from path
    project_name = Path(project_path).name if project_path else 'default'
    
    # Create attack_trees/project_name subdirectory
    strands_root = Path('${this.projectRoot}')
    attack_trees_dir = strands_root / 'output' / 'attack_trees' / project_name
    attack_trees_dir.mkdir(parents=True, exist_ok=True)
    
    successful_trees = [t for t in trees_result['attack_trees'] if 'mermaid_code' in t]
    
    for tree in successful_trees:
        # Generate filename from threat action
        threat_action = tree.get('threat_action', '')
        if not threat_action:
            threat_action = tree.get('threat_statement', 'unknown')
        
        # Remove filler words and create filename
        filler_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                       'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
                       'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                       'would', 'should', 'could', 'may', 'might', 'must', 'can', 'which',
                       'leads', 'resulting', 'reduced', 'that', 'this', 'these', 'those'}
        
        words = threat_action.lower().split()
        filtered_words = [w for w in words if w not in filler_words and len(w) > 2]
        filename_base = '_'.join(filtered_words[:6])
        filename_base = ''.join(c if c.isalnum() or c == '_' else '_' for c in filename_base)
        while '__' in filename_base:
            filename_base = filename_base.replace('__', '_')
        filename_base = filename_base.strip('_')
        
        filename = f"attack_tree_{filename_base}.md"
        filepath = attack_trees_dir / filename
        
        # Create markdown content with short title and full description
        threat_id = tree.get('threat_id', 'unknown')
        threat_category = tree.get('threat_category', 'Unknown')
        short_title = f"{threat_id} - {threat_category}"
        threat_description = tree.get('threat_description', tree.get('threat_statement', 'No description available'))
        
        content = f"""# Attack Tree: {short_title}

**Threat ID**: {threat_id}  
**Description**: {threat_description}

---

## Attack Tree Diagram

\`\`\`mermaid
{tree.get('mermaid_code', '')}
\`\`\`

## Attack Path Analysis

This attack tree represents the potential attack paths for the identified threat. Each node in the tree represents either:
- **Attack Goal** (orange): The ultimate objective
- **Attack Step** (red): Individual attack actions
- **Fact/Condition** (blue): Prerequisites or conditions
- **Mitigation** (green): Defensive measures

Review this attack tree to:
1. Identify critical attack paths
2. Implement appropriate security controls
3. Monitor for indicators of these attack patterns
4. Develop incident response procedures

---
*Generated by ThreatForest - Attack Tree Analysis*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

async def run():
    try:
        # Initialize logger with correct output directory BEFORE tool instantiation
        strands_root = Path('${this.projectRoot}')
        output_dir = strands_root / 'output'
        ThreatForestLogger.initialize(output_dir)
        
        params = json.loads(base64.b64decode('${paramsJson}').decode('utf-8'))
        tool = AttackTreeGeneratorTool()
        result = await tool.execute(
            threat_statements=params['threat_statements'],
            extracted_info=params['extracted_info'],
            bedrock_model=params['bedrock_model'],
            aws_profile=params.get('aws_profile')
        )
        
        # Save attack trees to disk
        if params.get('output_dir') and params.get('project_path'):
            save_attack_trees(result, params['output_dir'], params['project_path'])
        
        print(json.dumps({'success': True, 'data': result}))
    except Exception as e:
        import traceback
        logging.error(f"Attack tree generation failed: {e}")
        logging.error(traceback.format_exc())
        print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))

asyncio.run(run())
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => output += data.toString());
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Attack tree generation failed' });
        } else {
          try {
            const lines = output.trim().split('\n');
            let result = null;
            for (let i = lines.length - 1; i >= 0; i--) {
              try {
                result = JSON.parse(lines[i]);
                break;
              } catch (e) {
                continue;
              }
            }
            if (result) {
              resolve(result);
            } else {
              resolve({ success: false, error: 'No valid JSON output found' });
            }
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse attack tree output' });
          }
        }
      });
    });
  }

  async runSummaryGeneration(params: {
    attack_trees: any;
    extracted_info: any;
    output_dir: string;
  }): Promise<PythonResult> {
    return new Promise((resolve) => {
      const paramsJson = Buffer.from(JSON.stringify(params)).toString('base64');
      const script = `
import sys
import json
import asyncio
import base64
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.modules.tools.summary_generator_tool import SummaryGeneratorTool
from src.modules.utils.logger import ThreatForestLogger

async def run():
    try:
        # Initialize logger with correct output directory BEFORE tool instantiation
        strands_root = Path('${this.projectRoot}')
        output_dir = strands_root / 'output'
        ThreatForestLogger.initialize(output_dir)
        
        params = json.loads(base64.b64decode('${paramsJson}').decode('utf-8'))
        tool = SummaryGeneratorTool()
        result = await tool.execute(
            attack_trees=params['attack_trees'],
            extracted_info=params['extracted_info'],
            output_dir=params['output_dir']
        )
        print(json.dumps({'success': True, 'data': result}))
    except Exception as e:
        import traceback
        logging.error(f"Summary generation failed: {e}")
        logging.error(traceback.format_exc())
        print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))

asyncio.run(run())
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';

      python.stdout.on('data', (data) => output += data.toString());
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Summary generation failed' });
        } else {
          try {
            const lines = output.trim().split('\n');
            let result = null;
            for (let i = lines.length - 1; i >= 0; i--) {
              try {
                result = JSON.parse(lines[i]);
                break;
              } catch (e) {
                continue;
              }
            }
            if (result) {
              resolve(result);
            } else {
              resolve({ success: false, error: 'No valid JSON output found' });
            }
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse summary output' });
          }
        }
      });
    });
  }

  getProjectRoot(): string {
    return this.projectRoot;
  }

  // Run full workflow using Strands orchestrator
  async runOrchestratedWorkflow(params: {
    project_path: string;
    threat_model_path?: string;
    aws_profile?: string;
    bedrock_model: string;
    resume?: boolean;
  }, onProgress?: (event: ProgressEvent) => void): Promise<PythonResult> {
    return new Promise((resolve) => {
      const paramsJson = Buffer.from(JSON.stringify(params)).toString('base64');
      const script = `
import sys
import json
import asyncio
import base64
from pathlib import Path
sys.path.insert(0, '${this.projectRoot}')

from src.strands_agent import ThreatForestOrchestrator, ThreatForestConfig
from src.modules.utils.logger import ThreatForestLogger

async def run():
    try:
        # Initialize logger
        strands_root = Path('${this.projectRoot}')
        output_dir = strands_root / 'output'
        ThreatForestLogger.initialize(output_dir)
        
        # Decode params
        params = json.loads(base64.b64decode('${paramsJson}').decode('utf-8'))
        
        # Create config
        config = ThreatForestConfig(
            project_path=Path(params['project_path']),
            aws_profile=params.get('aws_profile'),
            bedrock_model=params['bedrock_model'],
            resume=params.get('resume', False)
        )
        
        # Run orchestrator
        orchestrator = ThreatForestOrchestrator(config)
        result = await orchestrator.execute_workflow()
        
        print(json.dumps({'success': True, 'data': result}))
    except Exception as e:
        import traceback
        print(json.dumps({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}))

asyncio.run(run())
`;

      const python = spawn(this.pythonPath, ['-c', script]);
      let output = '';
      let error = '';
      let partialLine = '';

      python.stdout.on('data', (data) => {
        const text = partialLine + data.toString();
        const lines = text.split('\n');
        partialLine = lines.pop() || '';
        
        for (const line of lines) {
          if (line.startsWith('PROGRESS:')) {
            try {
              const eventJson = line.substring(9);
              const event = JSON.parse(eventJson);
              if (onProgress) {
                onProgress(event);
              }
            } catch (e) {
              // Ignore malformed progress events
            }
          } else {
            output += line + '\n';
          }
        }
      });
      python.stderr.on('data', (data) => error += data.toString());

      python.on('close', (code) => {
        if (code !== 0) {
          resolve({ success: false, error: error || 'Orchestrated workflow failed' });
        } else {
          try {
            const lines = output.trim().split('\n');
            let result = null;
            for (let i = lines.length - 1; i >= 0; i--) {
              try {
                result = JSON.parse(lines[i]);
                break;
              } catch (e) {
                continue;
              }
            }
            if (result) {
              resolve(result);
            } else {
              resolve({ success: false, error: 'No valid JSON output found' });
            }
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse orchestrator output' });
          }
        }
      });
    });
  }
}
