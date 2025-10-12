import React from 'react';
import { render } from 'ink';
import { App } from './components/App';
import { PythonBridge } from './utils/pythonBridge';

const args = process.argv.slice(2);
const command = args[0];

async function handleCommand() {
  const bridge = new PythonBridge();

  switch (command) {
    case 'run':
    case undefined:
      // Start wizard
      render(<App />);
      break;

    case 'resume':
      // Check for saved state and resume
      const state = await bridge.loadState();
      if (state.success && state.data) {
        console.log('✓ Resuming from checkpoint...');
        console.log(`Stage: ${state.data.current_stage}`);
        console.log(`Started: ${new Date(state.data.started_at).toLocaleString()}`);
        render(<App />);
      } else {
        console.log('✗ No saved state found. Use "threatforest run" to start new session.');
        process.exit(1);
      }
      break;

    case 'status':
      // Show current workflow status
      const statusResult = await bridge.loadState();
      if (statusResult.success && statusResult.data) {
        console.log('\n📊 Workflow Status');
        console.log('='.repeat(50));
        console.log(`Stage: ${statusResult.data.current_stage}`);
        console.log(`Started: ${new Date(statusResult.data.started_at).toLocaleString()}`);
        console.log(`Last Updated: ${new Date(statusResult.data.last_updated).toLocaleString()}`);
        
        if (statusResult.data.setup_complete) console.log('✓ Setup complete');
        if (statusResult.data.context_files) console.log('✓ Context analysis complete');
        if (statusResult.data.extracted_info) console.log('✓ Information extraction complete');
        
        console.log('\nUse "threatforest resume" to continue');
      } else {
        console.log('No active workflow. Use "threatforest run" to start.');
      }
      break;

    case 'help':
    case '--help':
    case '-h':
      console.log(`
╔══════════════════════════════════════════════════════════╗
║              🛡️  THREATFOREST CLI                        ║
╚══════════════════════════════════════════════════════════╝

Usage: threatforest <command> [options]

Commands:
  run              Start new threat modeling session
  resume           Resume from last checkpoint
  status           Show current workflow status
  help             Show this help message

Examples:
  threatforest run
  threatforest resume
  threatforest status

For more information, visit: https://github.com/threatforest
`);
      break;

    default:
      console.log(`Unknown command: ${command}`);
      console.log('Use "threatforest help" for available commands');
      process.exit(1);
  }
}

handleCommand().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
