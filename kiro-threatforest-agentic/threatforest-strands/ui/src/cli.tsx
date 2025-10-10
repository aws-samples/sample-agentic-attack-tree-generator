#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { App } from './components/App';

const args = process.argv.slice(2);
const command = args[0];

if (command === 'run' || !command) {
  render(<App />);
} else if (command === 'cache') {
  console.log('Use: python -m threatforest.cli.cache_manager', args.slice(1).join(' '));
} else if (command === 'resume') {
  console.log('Resume functionality coming soon...');
} else if (command === 'status') {
  console.log('Status functionality coming soon...');
} else {
  console.log('Unknown command:', command);
  console.log('Available commands: run, resume, cache, status');
}
