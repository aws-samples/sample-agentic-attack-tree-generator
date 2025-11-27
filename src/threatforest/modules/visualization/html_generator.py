"""HTML generator for attack tree visualizations"""
import json
import base64
from typing import Dict, List, Any
from pathlib import Path
from ..utils.logger import ThreatForestLogger


class HTMLGenerator:
    """Generates interactive HTML visualizations for attack trees"""
    
    # Forest-themed color scheme for node types
    COLORS = {
        'attack': '#dc2626',      # Dark red - threat branches
        'goal': '#ea580c',        # Orange - end goals
        'fact': '#0369a1',        # Deep blue - starting conditions
        'mitigation': '#15803d',  # Forest green - protective leaves
        'technique': '#7c2d12'    # Brown - technique branches
    }
    
    def __init__(self):
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self._vis_network_script = None
    
    def _get_vis_network_script(self) -> str:
        """Load vis-network library script (cached after first load)"""
        if self._vis_network_script is None:
            script_path = Path(__file__).parent / 'templates' / 'vis-network.min.js'
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    self._vis_network_script = f.read()
                self.logger.debug(f"Loaded vis-network script from {script_path}")
            except Exception as e:
                self.logger.error(f"Failed to load vis-network script: {e}")
                # Fallback to CDN if local file not found
                self._vis_network_script = ''
        return self._vis_network_script
    
    def generate_dashboard_from_data(self, trees_data: List[Dict], output_path: str, summary_data: Dict = None):
        """
        Generate unified dashboard directly from structured tree data (no parsing)
        
        Args:
            trees_data: List of tree dictionaries with TTC mappings from TTC mapper
            output_path: Path to save dashboard HTML file
            summary_data: Optional dictionary with executive summary data
        """
        self.logger.info(f"Generating unified dashboard for {len(trees_data)} attack trees...")
        
        # Initialize mitigation mapper to fetch mitigations
        from threatforest.config import config
        from threatforest.modules.workflow.ttc_mappings import MitigationMapper
        mitigation_mapper = None
        try:
            if config.stix_bundle_path and Path(config.stix_bundle_path).exists():
                mitigation_mapper = MitigationMapper(str(config.stix_bundle_path))
        except Exception as e:
            self.logger.warning(f"Could not initialize mitigation mapper: {e}")
        
        # Convert structured data to visualization format
        all_trees = []
        for tree in trees_data:
            if not isinstance(tree, dict) or 'mermaid_code' not in tree:
                continue
            
            # Enrich TTC mappings with mitigations and URLs
            ttc_mappings = tree.get('ttc_mappings', [])
            if mitigation_mapper:
                for mapping in ttc_mappings:
                    technique_id = mapping.get('technique_id', '')
                    if technique_id:
                        # Construct proper MITRE ATT&CK URL (convert dots to slashes)
                        tech_url_id = technique_id.replace('.', '/')
                        mapping['technique_url'] = f"https://attack.mitre.org/techniques/{tech_url_id}/"
                        
                        # Fetch mitigations if not already present
                        if 'mitigations' not in mapping:
                            mitigations = mitigation_mapper.get_mitigations(technique_id)
                            mapping['mitigations'] = mitigations
            
            # Build parsed_data structure from tree dict
            parsed_data = {
                'metadata': {
                    'threat_id': tree.get('threat_id', 'unknown'),
                    'threat_statement': tree.get('threat_statement', tree.get('statement', '')),
                    'category': tree.get('threat_category', tree.get('category', 'Unknown'))
                },
                'nodes': {},
                'edges': [],
                'node_classes': {},
                'ttc_mappings': ttc_mappings
            }
            
            # Parse Mermaid to get nodes and edges
            mermaid_code = tree.get('mermaid_code', '')
            if mermaid_code:
                from .attack_tree_parser import AttackTreeParser
                parser = AttackTreeParser()
                nodes, edges, node_classes = parser._parse_mermaid(mermaid_code)
                parsed_data['nodes'] = nodes
                parsed_data['edges'] = edges
                parsed_data['node_classes'] = node_classes
            
            # Build visualization data
            vis_nodes, vis_edges = self._build_vis_data(parsed_data)
            
            self.logger.info(f"Tree {parsed_data['metadata']['threat_id']}: {len(ttc_mappings)} techniques, {len(vis_nodes)} total nodes")
            
            all_trees.append({
                'metadata': parsed_data['metadata'],
                'nodes': vis_nodes,
                'edges': vis_edges
            })
        
        if not all_trees:
            self.logger.warning("No trees to visualize")
            return
        
        # Sort trees by threat ID
        all_trees.sort(key=lambda t: t['metadata']['threat_id'])
        
        # Generate dashboard HTML with optional summary
        html = self._generate_dashboard_html(all_trees, summary_data)
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html)
        
        self.logger.info(f"✓ Dashboard saved with {len(all_trees)} trees: {output_path}")
    
    def generate_dashboard(self, markdown_files: List[str], output_path: str):
        """
        Generate unified dashboard with tabs for multiple attack trees
        
        Args:
            markdown_files: List of attack tree markdown file paths
            output_path: Path to save dashboard HTML file
        """
        self.logger.info(f"Generating unified dashboard for {len(markdown_files)} attack trees...")
        
        from .attack_tree_parser import AttackTreeParser
        parser = AttackTreeParser()
        
        # Parse all trees
        all_trees = []
        for md_file in markdown_files:
            try:
                parsed_data = parser.parse_file(md_file)
                vis_nodes, vis_edges = self._build_vis_data(parsed_data)
                all_trees.append({
                    'metadata': parsed_data['metadata'],
                    'nodes': vis_nodes,
                    'edges': vis_edges
                })
            except Exception as e:
                self.logger.warning(f"Failed to parse {md_file}: {e}")
                continue
        
        if not all_trees:
            self.logger.warning("No trees to visualize")
            return
        
        # Sort trees by threat ID for consistent tab ordering
        all_trees.sort(key=lambda t: t['metadata']['threat_id'])
        
        # Generate dashboard HTML
        html = self._generate_dashboard_html(all_trees)
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html)
        
        self.logger.info(f"✓ Dashboard saved: {output_path}")
    
    def generate(self, parsed_data: Dict[str, Any], output_path: str):
        """
        Generate HTML visualization from parsed attack tree data (single tree)
        
        Args:
            parsed_data: Parsed data from AttackTreeParser
            output_path: Path to save HTML file
        """
        self.logger.info(f"Generating HTML visualization: {output_path}")
        
        # Build nodes and edges for vis-network
        vis_nodes, vis_edges = self._build_vis_data(parsed_data)
        
        # Generate HTML
        html = self._generate_html(
            nodes=vis_nodes,
            edges=vis_edges,
            metadata=parsed_data['metadata']
        )
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html)
        
        self.logger.info(f"✓ HTML visualization saved: {output_path}")
    
    def _build_vis_data(self, parsed_data: Dict[str, Any]) -> tuple:
        """Build vis-network nodes and edges data"""
        vis_nodes = []
        vis_edges = []
        
        nodes = parsed_data['nodes']
        edges = parsed_data['edges']
        node_classes = parsed_data['node_classes']
        ttc_mappings = parsed_data['ttc_mappings']
        
        # Create attack tree nodes
        for node_id, node_data in nodes.items():
            node_class = node_classes.get(node_id, 'attack')
            color = self.COLORS.get(node_class, '#95a5a6')
            
            # Build tooltip
            tooltip = self._build_node_tooltip(
                label=node_data['label'],
                node_type=node_class.title(),
                color=color
            )
            
            vis_nodes.append({
                'id': node_id,
                'label': node_data['label'][:45] + '...' if len(node_data['label']) > 45 else node_data['label'],
                'color': color,
                'size': 30,
                'font': {'size': 14, 'color': '#ffffff'},
                'shadow': True,
                'borderWidth': 2,
                'borderWidthSelected': 3,
                'margin': {'top': 12, 'right': 16, 'bottom': 12, 'left': 16},
                'full_label': node_data['label'],
                'node_type': node_class,
                'node_color': color
            })
        
        # Create attack tree edges
        for edge in edges:
            vis_edges.append({
                'from': edge['from'],
                'to': edge['to'],
                'arrows': 'to',
                'color': {'color': '#95a5a6'},
                'width': 2
            })
        
        # Store TTC mappings in attack step nodes for sidebar display
        for mapping in ttc_mappings:
            attack_step = mapping['attack_step']
            
            # Find the attack step node and add techniques data
            for node in vis_nodes:
                if node['full_label'] == attack_step:
                    if 'techniques' not in node:
                        node['techniques'] = []
                    node['techniques'].append(mapping)
                    break
        
        return vis_nodes, vis_edges
    
    def _build_node_tooltip(self, label: str, node_type: str, color: str) -> str:
        """Build HTML tooltip for attack tree node"""
        return f"""
<div style='font-family: Arial; max-width: 300px; padding: 10px; background: white; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);'>
    <div style='background: {color}; color: white; padding: 6px; border-radius: 4px; margin-bottom: 8px; font-weight: bold; font-size: 12px;'>
        {node_type}
    </div>
    <div style='color: #2c3e50; font-size: 12px;'>
        {label}
    </div>
</div>
"""
    
    def _build_technique_tooltip(self, mapping: Dict[str, Any]) -> str:
        """Build HTML tooltip for technique node"""
        tactics_str = ', '.join(mapping.get('tactics', []))
        similarity = mapping.get('similarity', mapping.get('confidence', 0.0))
        
        return f"""
<div style='font-family: Arial; max-width: 350px; padding: 10px; background: white; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);'>
    <div style='background: {self.COLORS['technique']}; color: white; padding: 6px; border-radius: 4px; margin-bottom: 8px; font-weight: bold; font-size: 12px;'>
        MITRE ATT&CK Technique
    </div>
    <div style='margin-bottom: 8px;'>
        <div style='font-weight: bold; color: #2c3e50; font-size: 14px;'>{mapping['technique_id']}</div>
        <div style='color: #7f8c8d; font-size: 11px;'>{mapping.get('technique_name', '')}</div>
    </div>
    <div style='border-top: 1px solid #ecf0f1; padding-top: 6px; margin-top: 6px;'>
        <div style='margin-bottom: 4px;'><span style='color: #7f8c8d; font-size: 10px;'>Tactic:</span> <span style='color: #2c3e50; font-size: 11px;'>{tactics_str}</span></div>
        <div><span style='color: #7f8c8d; font-size: 10px;'>Similarity:</span> <span style='color: #2c3e50; font-size: 11px;'>{similarity:.1%}</span></div>
    </div>
    <div style='margin-top: 8px; font-size: 10px; color: #7f8c8d;'>
        Click for full details & mitigations
    </div>
</div>
"""
    
    def _build_mitigation_tooltip(self, mitigation: Dict[str, Any]) -> str:
        """Build HTML tooltip for mitigation node"""
        desc = mitigation.get('description', '')[:200]
        if len(mitigation.get('description', '')) > 200:
            desc += '...'
        
        return f"""
<div style='font-family: Arial; max-width: 350px; padding: 10px; background: white; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);'>
    <div style='background: {self.COLORS['mitigation']}; color: white; padding: 6px; border-radius: 4px; margin-bottom: 8px; font-weight: bold; font-size: 12px;'>
        🛡️ Mitigation
    </div>
    <div style='font-weight: bold; color: #2c3e50; font-size: 12px; margin-bottom: 6px;'>{mitigation['name']}</div>
    <div style='color: #7f8c8d; font-size: 10px;'>{desc}</div>
</div>
"""
    
    def _build_executive_summary_html(self, summary_data: Dict, all_trees: List[Dict]) -> str:
        """Build HTML content for executive summary tab"""
        project_info = summary_data.get('project_info', {})
        extraction_summary = summary_data.get('extraction_summary', {})
        high_severity = summary_data.get('high_severity_threats', [])
        
        # Key statistics
        total_threats = extraction_summary.get('total_threats', 0)
        high_severity_count = extraction_summary.get('high_severity_count', 0)
        total_techniques = sum(len(t.get('nodes', [])) for t in all_trees)
        
        html = '<div style="padding: 24px; max-width: 1400px; margin: 0 auto;">'
        
        # Hero section with statistics
        html += '''
        <div style="margin-bottom: 32px;">
            <h2 style="font-size: 28px; font-weight: 700; color: #111827; margin-bottom: 12px; letter-spacing: -0.5px;">📊 Executive Summary</h2>
            <p style="color: #4b5563; font-size: 14px; line-height: 1.6; margin-bottom: 8px;">This dashboard summarizes ThreatForest's agentic analysis of your application, including identified threats, attack trees, and MITRE ATT&CK mappings.</p>
            <p style="color: #6b7280; font-size: 12px; font-style: italic; margin-bottom: 24px; padding: 10px; background: #fef3c7; border-radius: 6px; border-left: 3px solid #f59e0b;">⚠️ AI-Generated Content: This analysis was produced by AI agents and should be reviewed for accuracy and completeness by security professionals.</p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 32px;">
        '''
        
        # Statistics cards - use special format for High Severity to show "X of Y"
        stats = [
            ('Total Threats', str(total_threats), '#6366f1'),
            ('High Severity', f'{high_severity_count} of {total_threats}', '#dc2626'),
            ('Attack Trees', str(len(all_trees)), '#15803d'),
            ('Total Nodes', str(total_techniques), '#ea580c')
        ]
        
        for label, value, color in stats:
            html += f'''
                <div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07); border-left: 4px solid {color};">
                    <div style="font-size: 36px; font-weight: 700; color: {color}; margin-bottom: 8px;">{value}</div>
                    <div style="font-size: 13px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">{label}</div>
                </div>
            '''
        
        html += '</div></div>'
        
        # Project Information
        html += '''
        <div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07); margin-bottom: 24px;">
            <h3 style="font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 20px;">🏢 Project Information</h3>
        '''
        
        project_fields = [
            ('Application Name', project_info.get('application_name', 'Unknown')),
            ('Architecture Type', project_info.get('architecture_type', 'Unknown')),
            ('Deployment Environment', project_info.get('deployment_environment', 'Unknown')),
            ('Industry Sector', project_info.get('sector', 'Unknown'))
        ]
        
        for label, value in project_fields:
            html += f'''
                <div style="margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #e5e7eb;">
                    <div style="font-size: 11px; font-weight: 700; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">{label}</div>
                    <div style="font-size: 14px; color: #111827; font-weight: 500;">{value}</div>
                </div>
            '''
        
        # Technologies
        technologies = project_info.get('technologies', [])
        if technologies:
            html += '''
                <div style="margin-top: 20px;">
                    <div style="font-size: 11px; font-weight: 700; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">Technology Stack</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            '''
            for tech in technologies:
                html += f'<span style="background: #f3f4f6; color: #374151; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 500;">{tech}</span>'
            html += '</div></div>'
        
        html += '</div>'
        
        # High Severity Threats with links to attack trees
        if high_severity:
            html += '''
            <div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07);">
                <h3 style="font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 20px;">⚠️ High Severity Threats</h3>
            '''
            
            # Build a lookup from threat_id to tree metadata for linking
            tree_lookup = {tree['metadata']['threat_id']: tree for tree in all_trees}
            
            for idx, threat in enumerate(high_severity, 1):
                threat_id = threat.get('id', 'Unknown')
                category = threat.get('category', 'Unknown')
                statement = threat.get('statement', threat.get('description', ''))
                
                # Find matching attack tree for this threat
                matching_tree = tree_lookup.get(threat_id)
                has_tree = matching_tree is not None
                node_count = len(matching_tree.get('nodes', [])) if matching_tree else 0
                
                # Build the link section
                if has_tree:
                    link_html = f'''
                        <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(220, 38, 38, 0.2); display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 11px; color: #6b7280;">{node_count} attack tree nodes</span>
                            <span onclick="switchTab('{threat_id}')" style="color: #dc2626; font-size: 12px; font-weight: 600; cursor: pointer; transition: opacity 0.2s;" onmouseover="this.style.opacity='0.7'" onmouseout="this.style.opacity='1'">View Attack Tree →</span>
                        </div>
                    '''
                else:
                    link_html = ''
                
                html += f'''
                    <div style="background: linear-gradient(135deg, rgba(220, 38, 38, 0.05) 0%, rgba(220, 38, 38, 0.02) 100%); border: 1px solid rgba(220, 38, 38, 0.2); border-left: 4px solid #dc2626; padding: 16px; border-radius: 8px; margin-bottom: 16px;">
                        <div style="font-weight: 700; color: #dc2626; font-size: 13px; margin-bottom: 8px;">Threat {idx}: {category}</div>
                        <div style="color: #374151; font-size: 13px; line-height: 1.6;">{statement}</div>
                        {link_html}
                    </div>
                '''
            
            html += '</div>'
        
        html += '</div>'
        
        return html
    
    def _generate_html(self, nodes: List[Dict], edges: List[Dict], metadata: Dict[str, Any]) -> str:
        """Generate complete HTML with embedded vis-network"""
        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)
        
        threat_id = metadata.get('threat_id', 'Unknown')
        category = metadata.get('category', 'Unknown')
        threat_statement = metadata.get('threat_statement', '')
        
        # Get vis-network script content
        vis_script = self._get_vis_network_script()
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Tree: {threat_id} - {category}</title>
    <script type="text/javascript">{vis_script}</script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .threat-id {{
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .threat-statement {{
            color: #34495e;
            font-size: 13px;
            line-height: 1.5;
            padding: 10px;
            background: #ecf0f1;
            border-radius: 4px;
        }}
        .legend {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .legend-title {{
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        .legend-items {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
        #mynetwork {{
            width: 100%;
            height: 700px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        #side-panel {{
            position: fixed;
            right: 20px;
            top: 20px;
            width: 400px;
            max-height: 90vh;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: none;
            overflow-y: auto;
            z-index: 1000;
        }}
        #side-panel.visible {{
            display: block;
        }}
        #close-panel {{
            position: sticky;
            top: 0;
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 8px 8px 0 0;
            padding: 10px;
            width: 100%;
            cursor: pointer;
            font-weight: bold;
            z-index: 10;
        }}
        #close-panel:hover {{
            background: #c0392b;
        }}
        #side-panel-content {{
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Attack Tree: {category}</h1>
        <div class="threat-id"><strong>Threat ID:</strong> {threat_id}</div>
        <div class="threat-statement">{threat_statement}</div>
    </div>
    
    <div class="legend">
        <div class="legend-title">Legend</div>
        <div class="legend-items">
            <div class="legend-item">
                <div class="legend-color" style="background: {self.COLORS['fact']}"></div>
                <span>Facts/Conditions</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: {self.COLORS['attack']}"></div>
                <span>Attack Steps</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: {self.COLORS['goal']}"></div>
                <span>Goals</span>
            </div>
        </div>
    </div>
    
    <div id="mynetwork"></div>
    
    <div id="side-panel">
        <button id="close-panel" onclick="closeSidePanel()">✕ Close</button>
        <div id="side-panel-content"></div>
    </div>
    
    <script>
        var nodes = new vis.DataSet({json.dumps(nodes, indent=8)});
        var edges = new vis.DataSet({json.dumps(edges, indent=8)});
        
        var container = document.getElementById('mynetwork');
        var data = {{ nodes: nodes, edges: edges }};
        
        var options = {{
            physics: {{
                enabled: true,
                solver: 'hierarchicalRepulsion',
                hierarchicalRepulsion: {{
                    centralGravity: 0.2,
                    springLength: 150,
                    springConstant: 0.01,
                    nodeDistance: 200,
                    damping: 0.09
                }},
                stabilization: {{
                    iterations: 200
                }}
            }},
            layout: {{
                hierarchical: {{
                    enabled: true,
                    direction: 'UD',
                    sortMethod: 'directed',
                    levelSeparation: 150,
                    nodeSpacing: 200
                }}
            }},
            interaction: {{
                hover: true,
                navigationButtons: true,
                keyboard: true
            }},
            edges: {{
                smooth: {{ type: 'cubicBezier' }}
            }}
        }};
        
        var network = new vis.Network(container, data, options);
        
        var sidePanel = document.getElementById('side-panel');
        var sidePanelContent = document.getElementById('side-panel-content');
        
        function closeSidePanel() {{
            sidePanel.classList.remove('visible');
            network.unselectAll();
        }}
        
        network.on('click', function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                
                if (node) {{
                    var panelHTML = buildNodePanel(node);
                    sidePanelContent.innerHTML = panelHTML;
                    sidePanel.classList.add('visible');
                    network.selectNodes([nodeId]);
                }}
            }} else {{
                closeSidePanel();
            }}
        }});
        
        function buildNodePanel(node) {{
            var html = '<div>';
            
            // Header
            html += '<div style="background: ' + node.color + '; color: white; padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; font-size: 16px;">';
            html += node.node_type.toUpperCase();
            html += '</div>';
            
            // Label
            html += '<div style="margin-bottom: 15px;">';
            html += '<div style="font-weight: 600; color: #7f8c8d; font-size: 10px; margin-bottom: 5px;">LABEL</div>';
            html += '<div style="color: #2c3e50; font-size: 14px;">' + escapeHtml(node.full_label || node.label) + '</div>';
            html += '</div>';
            
            // Technique-specific details
            if (node.technique_data) {{
                var tech = node.technique_data;
                
                html += '<div style="background: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 15px;">';
                html += '<div style="margin-bottom: 8px;"><span style="color: #7f8c8d; font-size: 10px;">Attack Step:</span> <span style="color: #2c3e50; font-size: 11px;">' + tech.attack_step + '</span></div>';
                html += '<div style="margin-bottom: 8px;"><span style="color: #7f8c8d; font-size: 10px;">Technique:</span> <span style="color: #2c3e50; font-size: 11px;">' + tech.technique_name + '</span></div>';
                html += '<div style="margin-bottom: 8px;"><span style="color: #7f8c8d; font-size: 10px;">Tactic:</span> <span style="color: #2c3e50; font-size: 11px;">' + tech.tactics.join(', ') + '</span></div>';
                html += '<div><span style="color: #7f8c8d; font-size: 10px;">Similarity:</span> <span style="color: #2c3e50; font-size: 11px;">' + (tech.similarity * 100).toFixed(1) + '%</span></div>';
                html += '</div>';
                
                // Mitigations
                if (tech.mitigations && tech.mitigations.length > 0) {{
                    html += '<div style="border-top: 2px solid #e9ecef; padding-top: 10px;">';
                    html += '<div style="font-weight: 600; color: #2c3e50; margin-bottom: 10px;">🛡️ Mitigations (' + tech.mitigations.length + ')</div>';
                    
                    tech.mitigations.forEach(function(mit) {{
                        html += '<div style="background: #e8f5e9; padding: 8px; border-radius: 4px; margin-bottom: 8px;">';
                        html += '<div style="font-weight: 600; color: #2c3e50; font-size: 11px; margin-bottom: 4px;">' + mit.name + '</div>';
                        html += '<div style="color: #666; font-size: 10px;">' + mit.description + '</div>';
                        html += '</div>';
                    }});
                    
                    html += '</div>';
                }}
                
                // Link to ATT&CK
                html += '<div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #e9ecef;">';
                html += '<a href="' + tech.technique_url + '" target="_blank" style="color: #3498db; text-decoration: none; font-size: 11px;">→ View on MITRE ATT&CK</a>';
                html += '</div>';
            }}
            
            // Mitigation-specific details
            if (node.mitigation_data) {{
                var mit = node.mitigation_data;
                html += '<div style="color: #2c3e50; font-size: 12px; line-height: 1.5;">';
                html += mit.description;
                html += '</div>';
            }}
            
            html += '</div>';
            return html;
        }}
        
        // Initial fit
        network.once('stabilizationIterationsDone', function() {{
            network.fit();
        }});
        
        console.log('Attack tree visualization loaded: ' + nodes.length + ' nodes, ' + edges.length + ' edges');
    </script>
</body>
</html>"""
    
    def _generate_dashboard_html(self, all_trees: List[Dict[str, Any]], summary_data: Dict = None) -> str:
        """Generate unified dashboard HTML with tabs for multiple trees and optional executive summary"""
        
        # Build executive summary HTML if data provided
        exec_summary_html = ''
        has_summary = summary_data is not None
        if has_summary:
            exec_summary_html = self._build_executive_summary_html(summary_data, all_trees)
        
        # Build tree data JSON and base64 encode it to avoid JavaScript escaping issues
        trees_data = []
        for tree in all_trees:
            threat_id = tree['metadata']['threat_id']
            trees_data.append({
                'id': threat_id,
                'metadata': tree['metadata'],
                'nodes': tree['nodes'],
                'edges': tree['edges']
            })
        
        trees_json = json.dumps(trees_data, ensure_ascii=True)
        # Base64 encode to safely embed complex JSON with special characters
        trees_json_b64 = base64.b64encode(trees_json.encode('utf-8')).decode('ascii')
        
        # Get vis-network script content
        vis_script = self._get_vis_network_script()
        
        # Build tabs HTML
        tabs_html = '<div class="tabs-container">\n'
        if has_summary:
            tabs_html += f'        <div class="tab {"active" if has_summary else ""}" onclick="switchTab(\'exec-summary\')">📊 Executive Summary</div>\n'
        
        for i, tree in enumerate(all_trees):
            threat_id = tree["metadata"]["threat_id"]
            category = tree["metadata"]["category"]
            is_active = 'active' if (i == 0 and not has_summary) else ''
            # Show friendly name: "Threat X: Category" instead of UUID
            tab_num = i + 1
            tabs_html += f'        <div class="tab {is_active}" onclick="switchTab(\'{threat_id}\')">Threat {tab_num}: {category}</div>\n'
        
        tabs_html += '    </div>'
        
        return rf"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ThreatForest Attack Trees Dashboard</title>
    <script type="text/javascript">{vis_script}</script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #f5f7fa 0%, #e9ecef 100%);
            color: #1f2937;
        }}
        .header {{
            background: linear-gradient(135deg, #166534 0%, #15803d 100%);
            color: white;
            padding: 28px 40px;
            box-shadow: 0 10px 25px rgba(22, 101, 52, 0.2), 0 5px 10px rgba(21, 128, 61, 0.15);
        }}
        h1 {{
            margin: 0 0 8px 0;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            opacity: 0.95;
            font-size: 15px;
            font-weight: 500;
        }}
        .tabs-container {{
            background: white;
            border-bottom: 2px solid #e5e7eb;
            padding: 0 24px;
            overflow-x: auto;
            white-space: nowrap;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            display: none;
        }}
        .tabs-container.visible {{
            display: block;
        }}
        .tab {{
            display: inline-block;
            padding: 16px 28px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            font-weight: 600;
            font-size: 14px;
            color: #6b7280;
            position: relative;
        }}
        .tab:hover {{
            background: linear-gradient(to bottom, rgba(99, 102, 241, 0.05), transparent);
            color: #4b5563;
            transform: translateY(-1px);
        }}
        .tab.active {{
            color: #6366f1;
            border-bottom-color: #6366f1;
            background: linear-gradient(to bottom, rgba(99, 102, 241, 0.08), transparent);
        }}
        .content {{
            padding: 20px;
        }}
        .tree-container {{
            display: none;
        }}
        .tree-container.active {{
            display: block;
        }}
        .tree-header {{
            background: white;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.05);
            border: 1px solid rgba(229, 231, 235, 0.8);
        }}
        .tree-title {{
            font-size: 22px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 12px;
            letter-spacing: -0.3px;
        }}
        .tree-statement {{
            color: #4b5563;
            font-size: 14px;
            line-height: 1.7;
            padding: 14px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.05) 0%, rgba(139, 92, 246, 0.05) 100%);
            border-radius: 8px;
            border-left: 4px solid #6366f1;
        }}
        .graph-and-sidebar {{
            display: flex;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .graph-container {{
            width: 60%;
            height: 800px;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            background: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.05);
            overflow: hidden;
        }}
        .side-panel {{
            width: 40%;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.05);
            border: 1px solid #e5e7eb;
            overflow-y: auto;
            max-height: 800px;
            transition: box-shadow 0.3s ease;
        }}
        .side-panel:hover {{
            box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1), 0 4px 6px rgba(0, 0, 0, 0.05);
        }}
        .side-panel-placeholder {{
            padding: 60px 24px;
            text-align: center;
            color: #9ca3af;
            font-size: 13px;
            line-height: 1.6;
        }}
        .legend {{
            background: white;
            padding: 20px 24px;
            border-radius: 12px;
            margin-top: 24px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.05);
            border: 1px solid #e5e7eb;
        }}
        .legend-title {{
            font-weight: 700;
            margin-bottom: 16px;
            color: #111827;
            font-size: 15px;
            letter-spacing: -0.2px;
        }}
        .legend-items {{
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            font-weight: 500;
            color: #374151;
        }}
        .legend-color {{
            width: 18px;
            height: 18px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🌳 ThreatForest: Attack Trees Dashboard</h1>
    </div>
    
    {tabs_html}
    
    <div class="content">
        {f'<div id="tree-exec-summary" class="tree-container {"active" if has_summary else ""}">{exec_summary_html}</div>' if has_summary else ''}
        {"".join([f'''
        <div id="tree-{tree["metadata"]["threat_id"]}" class="tree-container {"active" if i == 0 and not has_summary else ""}">
            {'<button onclick="switchTab(\'exec-summary\')" style="background: #6366f1; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(99, 102, 241, 0.3); transition: all 0.3s ease;" onmouseover="this.style.background=\'#4f46e5\'; this.style.transform=\'translateY(-1px)\'; this.style.boxShadow=\'0 4px 8px rgba(99, 102, 241, 0.4)\';" onmouseout="this.style.background=\'#6366f1\'; this.style.transform=\'translateY(0)\'; this.style.boxShadow=\'0 2px 4px rgba(99, 102, 241, 0.3)\';">← Executive Summary</button>' if has_summary else ''}
            <div class="tree-header">
                <div class="tree-title">Threat: {tree["metadata"]["category"]}</div>
                <div class="tree-id" style="font-size: 14px; color: #6b7280; font-weight: 600; margin-bottom: 12px;">{tree["metadata"]["threat_id"]}</div>
                <div class="tree-statement">{tree["metadata"]["threat_statement"]}</div>
            </div>
            <div class="graph-and-sidebar">
                <div id="graph-{tree["metadata"]["threat_id"]}" class="graph-container"></div>
                <div id="side-panel-{tree["metadata"]["threat_id"]}" class="side-panel">
                    <div class="side-panel-placeholder">Click a node to view details</div>
                </div>
            </div>
        </div>
        ''' for i, tree in enumerate(all_trees)])}
        
        <div id="legend-container" class="legend" style="display: none;">
            <div class="legend-title">Legend</div>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-color" style="background: {self.COLORS['fact']}"></div>
                    <span>Facts/Conditions</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: {self.COLORS['attack']}"></div>
                    <span>Attack Steps</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: {self.COLORS['goal']}"></div>
                    <span>Goals</span>
                </div>
            </div>
        </div>
    </div>
    
    <script type="text/plain" id="trees-data">
{trees_json_b64}
    </script>
    
    <script>
        var treesData = JSON.parse(atob(document.getElementById('trees-data').textContent.trim()));
        var networks = {{}};
        var hasSummary = {'true' if has_summary else 'false'};
        var currentTab = hasSummary ? 'exec-summary' : treesData[0].id;
        
        var networkOptions = {{
            physics: {{
                enabled: true,
                solver: 'hierarchicalRepulsion',
                hierarchicalRepulsion: {{
                    centralGravity: 0.1,
                    springLength: 200,
                    springConstant: 0.005,
                    nodeDistance: 200,
                    damping: 0.09,
                    avoidOverlap: 1
                }},
                stabilization: {{ iterations: 600 }}
            }},
            layout: {{
                hierarchical: {{
                    enabled: true,
                    direction: 'UD',
                    sortMethod: 'directed',
                    levelSeparation: 200
                }}
            }},
            interaction: {{
                navigationButtons: true,
                keyboard: true,
                dragNodes: true,
                dragView: true,
                zoomView: true
            }},
            edges: {{
                smooth: {{
                    enabled: true,
                    type: 'cubicBezier',
                    forceDirection: 'horizontal',
                    roundness: 0.5
                }}
            }}
        }};
        
        function initializeNetwork(treeId) {{
            if (networks[treeId]) return;
            
            var treeData = treesData.find(t => t.id === treeId);
            if (!treeData) return;
            
            var container = document.getElementById('graph-' + treeId);
            var sidePanel = document.getElementById('side-panel-' + treeId);
            var nodes = new vis.DataSet(treeData.nodes);
            var edges = new vis.DataSet(treeData.edges);
            
            var network = new vis.Network(container, {{ nodes: nodes, edges: edges }}, networkOptions);
            
            // Click handler - show sidebar
            network.on('click', function(params) {{
                if (params.nodes.length > 0) {{
                    var nodeId = params.nodes[0];
                    var node = nodes.get(nodeId);
                    if (node) {{
                        var panelHTML = buildNodePanel(node);
                        sidePanel.innerHTML = panelHTML;
                        network.selectNodes([nodeId]);
                    }}
                }} else {{
                    sidePanel.innerHTML = '<div class="side-panel-placeholder">Click a node to view details</div>';
                    network.unselectAll();
                }}
            }});
            
            // Double-click handler - expand/collapse mitigations for techniques
            network.on('doubleClick', function(params) {{
                if (params.nodes.length > 0) {{
                    var nodeId = params.nodes[0];
                    var node = nodes.get(nodeId);
                    
                    // Only handle technique nodes with mitigations
                    if (node && node.node_type === 'technique' && node.mitigation_ids && node.mitigation_ids.length > 0) {{
                        toggleMitigations(nodeId, node, nodes, edges);
                    }}
                }}
            }});
            
            // Function to toggle mitigation visibility with positioning
            function toggleMitigations(techId, techNode, nodesSet, edgesSet) {{
                var isExpanded = techNode.expanded || false;
                var mitigationIds = techNode.mitigation_ids || [];
                var techPos = network.getPositions([techId])[techId];
                
                if (isExpanded) {{
                    // Collapse - hide mitigations
                    mitigationIds.forEach(function(mitId) {{
                        nodesSet.update({{ id: mitId, hidden: true }});
                        var edgesToUpdate = edgesSet.get({{
                            filter: function(edge) {{ return edge.from === techId && edge.to === mitId; }}
                        }});
                        edgesToUpdate.forEach(function(edge) {{
                            edgesSet.update({{ id: edge.id, hidden: true }});
                        }});
                    }});
                    nodesSet.update({{ id: techId, label: techNode.label.replace('⊖', '⊕'), expanded: false }});
                }} else {{
                    // Expand - show mitigations near technique
                    mitigationIds.forEach(function(mitId, index) {{
                        nodesSet.update({{ id: mitId, hidden: false }});
                        // Position mitigation near technique (but not locked!)
                        network.moveNode(mitId, techPos.x + 150, techPos.y + (index * 80));
                        
                        var edgesToUpdate = edgesSet.get({{
                            filter: function(edge) {{ return edge.from === techId && edge.to === mitId; }}
                        }});
                        edgesToUpdate.forEach(function(edge) {{
                            edgesSet.update({{ id: edge.id, hidden: false }});
                        }});
                    }});
                    nodesSet.update({{ id: techId, label: techNode.label.replace('⊕', '⊖'), expanded: true }});
                }}
            }}
            
            // Position techniques near attack steps after stabilization (but keep draggable)
            network.once('stabilizationIterationsDone', function() {{
                var allNodes = nodes.get();
                var allEdges = edges.get();
                
                // Move techniques close to their parent attack steps
                allNodes.forEach(function(node) {{
                    if (node.node_type === 'technique') {{
                        var parentEdge = allEdges.find(function(e) {{
                            return e.to === node.id && !e.from.startsWith('tech');
                        }});
                        
                        if (parentEdge) {{
                            var parentPos = network.getPositions([parentEdge.from])[parentEdge.from];
                            // Move close to parent (but don't lock - still draggable!)
                            network.moveNode(node.id, parentPos.x + 50, parentPos.y + 80);
                        }}
                    }}
                }});
                
                network.setOptions({{ physics: false }});
                network.fit();
            }});
            
            networks[treeId] = {{ network: network, nodes: nodes, edges: edges }};
        }}
        
        function switchTab(treeId) {{
            // Update tab styling
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            if (event && event.target) {{
                event.target.classList.add('active');
            }}
            
            // Hide all tree containers
            document.querySelectorAll('.tree-container').forEach(container => {{
                container.classList.remove('active');
            }});
            
            // Show selected tree
            document.getElementById('tree-' + treeId).classList.add('active');
            
            // Show/hide tabs and legend based on current view
            var tabsContainer = document.querySelector('.tabs-container');
            var legendContainer = document.getElementById('legend-container');
            
            if (treeId === 'exec-summary') {{
                // Hide tabs and legend on exec summary
                tabsContainer.classList.remove('visible');
                legendContainer.style.display = 'none';
            }} else {{
                // Show tabs and legend on attack tree pages
                tabsContainer.classList.add('visible');
                legendContainer.style.display = 'block';
                // Initialize network if first time
                initializeNetwork(treeId);
            }}
            
            currentTab = treeId;
        }}
        
        // Helper function to escape HTML
        function escapeHtml(text) {{
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        // Smart formatting for mitigation text
        function formatMitigationText(text) {{
            if (!text) return '';
            
            var html = '';
            var lines = text.split('\\n');
            
            for (var i = 0; i < lines.length; i++) {{
                var line = lines[i].trim();
                if (!line) continue;
                
                // Section headers (end with colon)
                if (line.endsWith(':') && !line.startsWith('-')) {{
                    html += '<div style="font-weight: 700; color: #111827; font-size: 12px; margin-top: 12px; margin-bottom: 6px;">' + escapeHtml(line) + '</div>';
                }}
                // Bullet points
                else if (line.startsWith('- ')) {{
                    var content = line.substring(2);
                    // Check if it's a label (Use Case:, Implementation:)
                    if (content.indexOf(':') > 0 && content.indexOf(':') < 30) {{
                        var parts = content.split(':', 2);
                        html += '<div style="margin-left: 12px; margin-bottom: 6px; font-size: 11px;"><span style="font-weight: 600; color: #374151;">' + escapeHtml(parts[0]) + ':</span> <span style="color: #6b7280;">' + escapeHtml(parts[1]) + '</span></div>';
                    }} else {{
                        html += '<div style="margin-left: 12px; margin-bottom: 6px; font-size: 11px; color: #6b7280;">• ' + escapeHtml(content) + '</div>';
                    }}
                }}
                // Code blocks (backticks)
                else if (line.includes('`')) {{
                    line = line.replace(/`([^`]+)`/g, '<code style="background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-family: monospace;">$1</code>');
                    html += '<div style="margin-bottom: 6px; font-size: 11px; color: #6b7280;">' + line + '</div>';
                }}
                // Regular paragraphs
                else {{
                    html += '<div style="margin-bottom: 8px; font-size: 11px; color: #6b7280; line-height: 1.6;">' + escapeHtml(line) + '</div>';
                }}
            }}
            
            return html;
        }}
        
        // Accordion toggle function
        function toggleAccordion(id) {{
            var content = document.getElementById(id);
            var icon = document.getElementById(id + '-icon');
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                icon.textContent = '▼';
            }} else {{
                content.style.display = 'none';
                icon.textContent = '▶';
            }}
        }}
        
        function buildNodePanel(node) {{
            var html = '<div style="padding: 15px;">';
            
            // Header with node type - modern gradient
            var headerColor = node.node_color || node.color;
            html += '<div style="background: linear-gradient(135deg, ' + headerColor + ' 0%, ' + headerColor + 'dd 100%); color: white; padding: 14px 16px; border-radius: 8px; margin-bottom: 18px; font-weight: 700; font-size: 14px; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            html += escapeHtml(node.node_type.toUpperCase());
            html += '</div>';
            
            // Node ID - modern card
            html += '<div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 16px;">';
            html += '<div style="font-weight: 700; color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Node ID</div>';
            html += '<div style="color: #111827; font-size: 12px; font-family: monospace; font-weight: 600;">' + escapeHtml(node.id) + '</div>';
            html += '</div>';
            
            // Label/Description - modern card
            html += '<div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 16px;">';
            html += '<div style="font-weight: 700; color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">Description</div>';
            html += '<div style="color: #374151; font-size: 13px; line-height: 1.6;">' + escapeHtml(node.full_label || node.label) + '</div>';
            html += '</div>';
            
            // MITRE Techniques (for attack steps with TTC mappings)
            if (node.techniques && node.techniques.length > 0) {{
                html += '<div style="border-top: 2px solid #e5e7eb; padding-top: 18px; margin-top: 18px;">';
                html += '<div style="font-weight: 700; color: #111827; margin-bottom: 14px; font-size: 14px; letter-spacing: -0.2px;">⚡ MITRE ATT&CK Techniques (' + node.techniques.length + ')</div>';
                
                node.techniques.forEach(function(tech, techIdx) {{
                    var similarity = tech.similarity || tech.confidence || 0;
                    var accordionId = 'tech-' + techIdx;
                    
                    // Technique card
                    html += '<div style="background: linear-gradient(135deg, rgba(124, 45, 18, 0.08) 0%, rgba(124, 45, 18, 0.05) 100%); border: 1px solid rgba(124, 45, 18, 0.2); border-left: 4px solid #7c2d12; padding: 12px; border-radius: 8px; margin-bottom: 16px;">';
                    
                    // Technique header
                    html += '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">';
                    html += '<div>';
                    html += '<div style="font-weight: 700; color: #111827; font-size: 13px;">' + escapeHtml(tech.technique_id) + '</div>';
                    html += '<div style="color: #6b7280; font-size: 11px; margin-top: 2px;">' + escapeHtml(tech.technique_name) + '</div>';
                    html += '</div>';
                    html += '<div style="background: #dcfce7; color: #166534; padding: 3px 8px; border-radius: 8px; font-size: 10px; font-weight: 700;">' + (similarity * 100).toFixed(0) + '%</div>';
                    html += '</div>';
                    
                    // Technique description (if available)
                    if (tech.technique_description) {{
                        html += '<div style="color: #6b7280; font-size: 11px; line-height: 1.5; margin-bottom: 10px;">' + escapeHtml(tech.technique_description) + '</div>';
                    }}
                    
                    // Tactic badge
                    if (tech.tactics && tech.tactics.length > 0) {{
                        html += '<div style="margin-bottom: 10px;"><span style="display: inline-block; background: #dbeafe; color: #1e40af; padding: 3px 8px; border-radius: 8px; font-size: 10px; font-weight: 600;">' + escapeHtml(tech.tactics.join(', ')) + '</span></div>';
                    }}
                    
                    // Expandable mitigations
                    if (tech.mitigations && tech.mitigations.length > 0) {{
                        html += '<div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(124, 45, 18, 0.2);">';
                        html += '<div onclick="toggleAccordion(\'' + accordionId + '\')" style="cursor: pointer; font-weight: 700; color: #111827; font-size: 11px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">';
                        html += '<span>🛡️ Mitigations (' + tech.mitigations.length + ')</span>';
                        html += '<span id="' + accordionId + '-icon" style="font-size: 16px;">▼</span>';
                        html += '</div>';
                        
                        html += '<div id="' + accordionId + '" style="display: block;">';
                        tech.mitigations.forEach(function(mit, mitIdx) {{
                            html += '<div style="background: rgba(21, 128, 61, 0.08); padding: 14px; border-radius: 6px; margin-bottom: 12px;">';
                            html += '<div style="font-weight: 700; color: #111827; font-size: 13px; margin-bottom: 10px;">🛡️ ' + escapeHtml(mit.name) + '</div>';
                            if (mit.description) {{
                                html += formatMitigationText(mit.description);
                            }}
                            html += '</div>';
                        }});
                        html += '</div>';
                        
                        html += '</div>';
                    }}
                    
                    // Link to MITRE
                    if (tech.technique_url) {{
                        html += '<div style="margin-top: 10px;">';
                        html += '<a href="' + tech.technique_url + '" target="_blank" style="color: #3b82f6; text-decoration: none; font-size: 10px; font-weight: 600;">→ View on MITRE ATT&CK</a>';
                        html += '</div>';
                    }}
                    
                    html += '</div>';
                }});
                
                html += '</div>';
            }}
            
            html += '</div>';
            return html;
        }}
        
        // Initialize first tree (only if not showing exec summary first)
        if (!hasSummary) {{
            initializeNetwork(treesData[0].id);
            // Show tabs and legend for attack tree view
            document.querySelector('.tabs-container').classList.add('visible');
            document.getElementById('legend-container').style.display = 'block';
        }}
        // If showing exec summary first, tabs and legend stay hidden (default state)
        
        console.log('Dashboard loaded with ' + treesData.length + ' attack trees' + (hasSummary ? ' and executive summary' : ''));
    </script>
</body>
</html>"""
