"""
STIX processing functionality for MITRE ATT&CK technique mapping.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .models import STIXTechnique, AttackStep
from .exceptions import STIXProcessingError
from .utils import get_logger


@dataclass
class TechniqueMatch:
    """Represents a match between an attack step and MITRE technique."""
    technique: STIXTechnique
    confidence: float
    reasoning: str


class STIXProcessor:
    """Processes STIX bundle data to extract MITRE ATT&CK techniques."""
    
    def __init__(self, bundle_path: str):
        self.bundle_path = Path(bundle_path)
        self.logger = get_logger(__name__)
        self.techniques: Dict[str, STIXTechnique] = {}
        self.tactics: Dict[str, str] = {}
        self._load_stix_bundle()
    
    def _load_stix_bundle(self) -> None:
        """Load and parse STIX bundle file."""
        if not self.bundle_path.exists():
            raise STIXProcessingError(f"STIX bundle file not found: {self.bundle_path}")
        
        try:
            with open(self.bundle_path, 'r', encoding='utf-8') as f:
                bundle_data = json.load(f)
            
            self.logger.info(f"Loading STIX bundle: {self.bundle_path}")
            
            if 'objects' not in bundle_data:
                raise STIXProcessingError("Invalid STIX bundle: missing 'objects' field")
            
            # Process STIX objects
            self._process_stix_objects(bundle_data['objects'])
            
            self.logger.info(f"Loaded {len(self.techniques)} techniques and {len(self.tactics)} tactics")
            
        except json.JSONDecodeError as e:
            raise STIXProcessingError(f"Invalid JSON in STIX bundle: {e}")
        except Exception as e:
            raise STIXProcessingError(f"Error loading STIX bundle: {e}")
    
    def _process_stix_objects(self, objects: List[Dict[str, Any]]) -> None:
        """Process STIX objects to extract techniques and tactics."""
        for obj in objects:
            try:
                obj_type = obj.get('type', '')
                
                if obj_type == 'attack-pattern':
                    self._process_attack_pattern(obj)
                elif obj_type == 'x-mitre-tactic':
                    self._process_tactic(obj)
                
            except Exception as e:
                self.logger.warning(f"Error processing STIX object {obj.get('id', 'unknown')}: {e}")
    
    def _process_attack_pattern(self, obj: Dict[str, Any]) -> None:
        """Process attack pattern (technique) object."""
        try:
            # Extract basic information
            technique_id = obj.get('id', '')
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            # Extract external references for MITRE ATT&CK ID
            external_refs = obj.get('external_references', [])
            mitre_id = ''
            
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    break
            
            # Extract kill chain phases (tactics)
            kill_chain_phases = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    kill_chain_phases.append(phase.get('phase_name', ''))
            
            # Determine if this is a sub-technique
            sub_technique_id = None
            if '.' in mitre_id:
                parts = mitre_id.split('.')
                mitre_id = parts[0]
                sub_technique_id = mitre_id + '.' + parts[1]
            
            # Create STIXTechnique object
            technique = STIXTechnique(
                id=technique_id,
                name=name,
                description=description,
                tactic=kill_chain_phases[0] if kill_chain_phases else '',
                technique_id=mitre_id,
                sub_technique_id=sub_technique_id,
                kill_chain_phases=kill_chain_phases
            )
            
            self.techniques[technique_id] = technique
            
            # Also index by MITRE ID for easier lookup
            if mitre_id:
                self.techniques[mitre_id] = technique
            if sub_technique_id:
                self.techniques[sub_technique_id] = technique
                
        except Exception as e:
            self.logger.warning(f"Error processing attack pattern: {e}")
    
    def _process_tactic(self, obj: Dict[str, Any]) -> None:
        """Process tactic object."""
        try:
            tactic_id = obj.get('id', '')
            name = obj.get('name', '')
            
            # Extract shortname from external references
            external_refs = obj.get('external_references', [])
            shortname = ''
            
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    shortname = ref.get('external_id', '')
                    break
            
            self.tactics[tactic_id] = name
            if shortname:
                self.tactics[shortname] = name
                
        except Exception as e:
            self.logger.warning(f"Error processing tactic: {e}")
    
    def get_technique_by_id(self, technique_id: str) -> Optional[STIXTechnique]:
        """Get technique by MITRE ATT&CK ID."""
        return self.techniques.get(technique_id)
    
    def search_techniques(self, query: str, limit: int = 10) -> List[STIXTechnique]:
        """
        Search techniques by name or description.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching techniques
        """
        query_lower = query.lower()
        matches = []
        
        for technique in self.techniques.values():
            # Avoid duplicates (same technique indexed by different keys)
            if technique in matches:
                continue
            
            score = 0
            
            # Check name match
            if query_lower in technique.name.lower():
                score += 10
            
            # Check description match
            if query_lower in technique.description.lower():
                score += 5
            
            # Check tactic match
            if query_lower in technique.tactic.lower():
                score += 3
            
            if score > 0:
                matches.append((technique, score))
        
        # Sort by score and return top results
        matches.sort(key=lambda x: x[1], reverse=True)
        return [match[0] for match in matches[:limit]]
    
    def get_techniques_by_tactic(self, tactic: str) -> List[STIXTechnique]:
        """Get all techniques for a specific tactic."""
        tactic_lower = tactic.lower()
        matching_techniques = []
        
        for technique in self.techniques.values():
            # Avoid duplicates
            if technique in matching_techniques:
                continue
            
            if tactic_lower in technique.tactic.lower() or tactic_lower in [phase.lower() for phase in technique.kill_chain_phases]:
                matching_techniques.append(technique)
        
        return matching_techniques
    
    def get_bundle_summary(self) -> Dict[str, Any]:
        """Get summary of loaded STIX bundle."""
        # Count unique techniques (avoid duplicates from indexing)
        unique_techniques = set()
        technique_by_tactic = {}
        
        for technique in self.techniques.values():
            if technique.id not in unique_techniques:
                unique_techniques.add(technique.id)
                
                for tactic in technique.kill_chain_phases:
                    if tactic not in technique_by_tactic:
                        technique_by_tactic[tactic] = 0
                    technique_by_tactic[tactic] += 1
        
        return {
            'total_techniques': len(unique_techniques),
            'total_tactics': len(self.tactics),
            'techniques_by_tactic': technique_by_tactic,
            'bundle_path': str(self.bundle_path)
        }


class STIXMapper:
    """Maps attack steps to MITRE ATT&CK techniques using semantic analysis."""
    
    def __init__(self, stix_processor: STIXProcessor, confidence_threshold: float = 0.8):
        self.stix_processor = stix_processor
        self.confidence_threshold = confidence_threshold
        self.logger = get_logger(__name__)
        
        # Keywords for different attack categories
        self.attack_keywords = {
            'initial-access': [
                'phishing', 'spear phishing', 'drive-by', 'exploit public', 'external remote',
                'hardware additions', 'replication', 'supply chain', 'trusted relationship',
                'valid accounts'
            ],
            'execution': [
                'command line', 'compiled html', 'control panel', 'dynamic data exchange',
                'exploitation', 'graphical user', 'installutil', 'launchctl', 'local job',
                'mshta', 'powershell', 'regsvcs', 'regsvr32', 'rundll32', 'scheduled task',
                'scripting', 'service execution', 'signed binary', 'signed script',
                'source', 'space after filename', 'third-party software', 'trap',
                'trusted developer', 'user execution', 'windows management', 'winlogon'
            ],
            'persistence': [
                'account manipulation', 'accessibility features', 'appinit dlls', 'application shimming',
                'authentication package', 'bios', 'bootkit', 'browser extensions', 'change default',
                'component firmware', 'component object model', 'create account', 'dll search',
                'external remote services', 'file system permissions', 'hidden files',
                'hooking', 'hypervisor', 'image file execution', 'implant container',
                'kernel modules', 'launchctl', 'lc load dylib', 'local job scheduling',
                'login item', 'logon scripts', 'lsass driver', 'modify existing service',
                'netsh helper', 'new service', 'office application', 'path interception',
                'plist modification', 'port knocking', 'port monitors', 'rc scripts',
                'redundant access', 'registry run', 'scheduled task', 'screensaver',
                'security support provider', 'server software component', 'service registry',
                'setuid', 'shortcut modification', 'startup items', 'system firmware',
                'systemd service', 'time providers', 'trap', 'valid accounts', 'web shell',
                'winlogon helper', 'wmi event'
            ],
            'privilege-escalation': [
                'access token manipulation', 'accessibility features', 'appinit dlls',
                'application shimming', 'bypass user account', 'dll search order',
                'dylib hijacking', 'elevated execution', 'exploitation', 'extra window',
                'file system permissions', 'hooking', 'image file execution', 'kernel exploitation',
                'launch daemon', 'new service', 'path interception', 'plist modification',
                'port monitors', 'process injection', 'scheduled task', 'service registry',
                'setuid', 'startup items', 'sudo', 'sudo caching', 'valid accounts',
                'web shell'
            ],
            'defense-evasion': [
                'access token manipulation', 'bitsadmin', 'binary padding', 'bypass user account',
                'clear command history', 'code signing', 'compiled html', 'component firmware',
                'component object model', 'connection proxy', 'control panel', 'deobfuscate',
                'disabling security tools', 'dll search order', 'dll side-loading',
                'exploitation', 'extra window', 'file deletion', 'file system logical',
                'gatekeeper bypass', 'group policy modification', 'hidden files', 'hidden users',
                'hidden window', 'hooking', 'image file execution', 'indicator blocking',
                'indicator removal', 'indirect command', 'install root certificate',
                'installutil', 'launchctl', 'lc main hijacking', 'masquerading', 'modify registry',
                'mshta', 'network share connection', 'ntfs file attributes', 'obfuscated files',
                'plist modification', 'port knocking', 'process doppelganging', 'process hollowing',
                'process injection', 'redundant access', 'regsvcs', 'regsvr32', 'rootkit',
                'rundll32', 'scripting', 'signed binary', 'signed script', 'software packing',
                'space after filename', 'template injection', 'timestomp', 'trusted developer',
                'valid accounts', 'virtualization', 'web service'
            ],
            'credential-access': [
                'account manipulation', 'bash history', 'brute force', 'credential dumping',
                'credentials from web', 'credentials in files', 'credentials in registry',
                'exploitation', 'forced authentication', 'hooking', 'input capture',
                'kerberoasting', 'keychain', 'llmnr', 'network sniffing', 'password filter',
                'private keys', 'securityd memory', 'two-factor authentication'
            ],
            'discovery': [
                'account discovery', 'application window', 'browser bookmark', 'domain trust',
                'file and directory', 'network service', 'network share', 'network sniffing',
                'password policy', 'peripheral device', 'permission groups', 'process discovery',
                'query registry', 'remote system', 'security software', 'system information',
                'system network configuration', 'system network connections', 'system owner',
                'system service', 'system time', 'virtualization'
            ],
            'lateral-movement': [
                'application deployment', 'distributed component', 'exploitation', 'internal spearphishing',
                'logon scripts', 'pass the hash', 'pass the ticket', 'remote desktop',
                'remote file copy', 'remote services', 'replication', 'shared webroot',
                'ssh hijacking', 'taint shared content', 'third-party software', 'windows admin'
            ],
            'collection': [
                'audio capture', 'automated collection', 'clipboard data', 'data from information',
                'data from local', 'data from network', 'data from removable', 'data staged',
                'email collection', 'input capture', 'man in the browser', 'screen capture',
                'video capture'
            ],
            'command-and-control': [
                'commonly used port', 'communication through', 'connection proxy', 'custom command',
                'custom cryptographic', 'data encoding', 'data obfuscation', 'domain fronting',
                'domain generation', 'fallback channels', 'multi-stage channels', 'multiband',
                'multilayer encryption', 'port knocking', 'remote access tools', 'remote file copy',
                'standard application', 'standard cryptographic', 'standard non-application',
                'uncommonly used port', 'web service'
            ],
            'exfiltration': [
                'automated exfiltration', 'data compressed', 'data encrypted', 'data transfer',
                'exfiltration over alternative', 'exfiltration over command', 'exfiltration over other',
                'exfiltration over physical', 'scheduled transfer'
            ],
            'impact': [
                'data destruction', 'data encrypted', 'defacement', 'disk structure wipe',
                'endpoint denial', 'firmware corruption', 'inhibit system recovery',
                'network denial', 'resource hijacking', 'runtime data manipulation',
                'service stop', 'stored data manipulation', 'system shutdown'
            ]
        }
    
    def map_attack_steps(self, attack_steps: List[AttackStep]) -> List[AttackStep]:
        """
        Map attack steps to MITRE ATT&CK techniques.
        
        Args:
            attack_steps: List of attack steps to map
            
        Returns:
            List of attack steps with MITRE technique mappings
        """
        self.logger.info(f"Mapping {len(attack_steps)} attack steps to MITRE ATT&CK techniques")
        
        mapped_steps = []
        
        for step in attack_steps:
            # Only map attack-type steps
            if step.node_type == 'attack':
                matches = self._find_technique_matches(step)
                
                # Apply mappings that meet confidence threshold
                high_confidence_matches = [
                    match for match in matches 
                    if match.confidence >= self.confidence_threshold
                ]
                
                if high_confidence_matches:
                    step.mitre_techniques = [match.technique.technique_id for match in high_confidence_matches]
                    step.confidence_score = max(match.confidence for match in high_confidence_matches)
                    
                    self.logger.debug(f"Mapped {step.id} to {len(high_confidence_matches)} techniques")
            
            mapped_steps.append(step)
        
        mapped_count = sum(1 for step in mapped_steps if step.mitre_techniques)
        self.logger.info(f"Successfully mapped {mapped_count} attack steps to MITRE techniques")
        
        return mapped_steps
    
    def _find_technique_matches(self, attack_step: AttackStep) -> List[TechniqueMatch]:
        """Find matching MITRE techniques for an attack step."""
        matches = []
        description_lower = attack_step.description.lower()
        
        # Search for direct keyword matches
        for tactic, keywords in self.attack_keywords.items():
            for keyword in keywords:
                if keyword in description_lower:
                    # Get techniques for this tactic
                    tactic_techniques = self.stix_processor.get_techniques_by_tactic(tactic)
                    
                    for technique in tactic_techniques:
                        confidence = self._calculate_confidence(attack_step, technique, keyword)
                        
                        if confidence > 0.5:  # Minimum threshold for consideration
                            match = TechniqueMatch(
                                technique=technique,
                                confidence=confidence,
                                reasoning=f"Keyword '{keyword}' match in {tactic} tactic"
                            )
                            matches.append(match)
        
        # Search by technique name/description similarity
        search_results = self.stix_processor.search_techniques(attack_step.description, limit=5)
        
        for technique in search_results:
            confidence = self._calculate_semantic_confidence(attack_step, technique)
            
            if confidence > 0.5:
                match = TechniqueMatch(
                    technique=technique,
                    confidence=confidence,
                    reasoning="Semantic similarity match"
                )
                matches.append(match)
        
        # Remove duplicates and sort by confidence
        unique_matches = {}
        for match in matches:
            key = match.technique.technique_id
            if key not in unique_matches or match.confidence > unique_matches[key].confidence:
                unique_matches[key] = match
        
        sorted_matches = sorted(unique_matches.values(), key=lambda x: x.confidence, reverse=True)
        return sorted_matches[:3]  # Return top 3 matches
    
    def _calculate_confidence(self, attack_step: AttackStep, technique: STIXTechnique, keyword: str) -> float:
        """Calculate confidence score for a technique match."""
        confidence = 0.0
        
        step_desc_lower = attack_step.description.lower()
        technique_name_lower = technique.name.lower()
        technique_desc_lower = technique.description.lower()
        
        # Keyword match in step description
        if keyword in step_desc_lower:
            confidence += 0.3
        
        # Technique name similarity
        if any(word in technique_name_lower for word in step_desc_lower.split()):
            confidence += 0.4
        
        # Description similarity
        common_words = set(step_desc_lower.split()) & set(technique_desc_lower.split())
        if len(common_words) > 2:
            confidence += 0.3
        elif len(common_words) > 0:
            confidence += 0.1
        
        # Boost for exact matches
        if keyword in technique_name_lower:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_semantic_confidence(self, attack_step: AttackStep, technique: STIXTechnique) -> float:
        """Calculate semantic similarity confidence."""
        step_words = set(attack_step.description.lower().split())
        technique_words = set(technique.name.lower().split()) | set(technique.description.lower().split())
        
        # Jaccard similarity
        intersection = step_words & technique_words
        union = step_words | technique_words
        
        if not union:
            return 0.0
        
        jaccard = len(intersection) / len(union)
        
        # Boost for important words
        important_words = {'attack', 'exploit', 'compromise', 'access', 'execute', 'escalate'}
        important_matches = intersection & important_words
        
        confidence = jaccard
        if important_matches:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def get_mapping_summary(self, attack_steps: List[AttackStep]) -> Dict[str, Any]:
        """Generate summary of technique mapping results."""
        total_steps = len(attack_steps)
        attack_steps_only = [step for step in attack_steps if step.node_type == 'attack']
        mapped_steps = [step for step in attack_steps_only if step.mitre_techniques]
        
        # Count techniques by tactic
        technique_counts = {}
        all_techniques = set()
        
        for step in mapped_steps:
            for technique_id in step.mitre_techniques:
                technique = self.stix_processor.get_technique_by_id(technique_id)
                if technique:
                    all_techniques.add(technique_id)
                    for tactic in technique.kill_chain_phases:
                        technique_counts[tactic] = technique_counts.get(tactic, 0) + 1
        
        return {
            'total_steps': total_steps,
            'attack_steps': len(attack_steps_only),
            'mapped_steps': len(mapped_steps),
            'mapping_rate': len(mapped_steps) / len(attack_steps_only) if attack_steps_only else 0,
            'unique_techniques': len(all_techniques),
            'techniques_by_tactic': technique_counts
        }