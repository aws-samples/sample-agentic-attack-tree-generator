import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

/**
 * Vite plugin that provides a dev-only API endpoint for persisting
 * attack tree edits back to the threatforest_data.json file on disk.
 * 
 * PATCH /api/test/node — updates a node's fields in the JSON file
 * PATCH /api/test/flow — updates flow-level fields in the JSON file
 */
function attackFlowEditorPlugin() {
  const DATA_PATH = path.resolve(__dirname, '../sample-applications/vehicle-platform/threatforest/attack_trees/threatforest_data.json');

  return {
    name: 'attack-flow-editor',
    configureServer(server) {
      // PATCH /api/test/node — update a node's fields
      server.middlewares.use('/api/test/node', (req, res, next) => {
        if (req.method !== 'PATCH') return next();
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
          try {
            const { threatId, nodeId, fields } = JSON.parse(body);
            const data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8'));
            const tree = data.attack_trees?.find(t => t.threat_id === threatId);
            if (!tree) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Threat not found' }));
              return;
            }
            // Update attack_steps
            const step = tree.attack_steps?.find(s => s.node_id === nodeId);
            if (step) {
              if (fields.label !== undefined) step.label = fields.label;
              if (fields.description !== undefined) step.description = fields.description;
            }
            // Update mermaid node label if label changed (for visual consistency)
            // Write back
            fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
            // Also update the public copy
            const publicPath = path.resolve(__dirname, 'public/test-data.json');
            fs.writeFileSync(publicPath, JSON.stringify(data, null, 2));
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'updated', threatId, nodeId }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
      });

      // PATCH /api/test/flow — update flow-level fields
      server.middlewares.use('/api/test/flow', (req, res, next) => {
        if (req.method !== 'PATCH') return next();
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
          try {
            const { threatId, fields } = JSON.parse(body);
            const data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8'));
            const tree = data.attack_trees?.find(t => t.threat_id === threatId);
            if (!tree) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Threat not found' }));
              return;
            }
            if (fields.threat_statement !== undefined) tree.threat_statement = fields.threat_statement;
            if (fields.threat_category !== undefined) tree.threat_category = fields.threat_category;
            if (fields.priority !== undefined) tree.priority = fields.priority;
            fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
            const publicPath = path.resolve(__dirname, 'public/test-data.json');
            fs.writeFileSync(publicPath, JSON.stringify(data, null, 2));
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'updated', threatId }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), attackFlowEditorPlugin()],
  server: {
    proxy: {
      '/api/applications': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/paused-runs': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/runs': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/config': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/filesystem': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
