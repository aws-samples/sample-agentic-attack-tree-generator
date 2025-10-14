"""Tests for parser chain (Tasks 11.1-11.5)"""
import unittest
import tempfile
import json
from pathlib import Path
from threatforest.parsers import (
    ThreatParser, ParserChain, JSONThreatParser,
    YAMLThreatParser, MarkdownThreatParser, ThreatComposerParser
)


class TestJSONParser(unittest.TestCase):
    """Test JSON parser"""
    
    def setUp(self):
        """Create temporary directory and test file"""
        self.temp_dir = tempfile.mkdtemp()
        self.json_file = Path(self.temp_dir) / "test.json"
        self.json_file.write_text('{"threats": [{"id": "T001"}]}')
    
    def test_can_parse_json_file(self):
        """Test JSON parser recognizes JSON files"""
        parser = JSONThreatParser()
        self.assertTrue(parser.can_parse(self.json_file))
    
    def test_can_parse_tc_file(self):
        """Test JSON parser recognizes .tc files"""
        tc_file = Path(self.temp_dir) / "test.tc"
        tc_file.write_text('{"threats": []}')
        
        parser = JSONThreatParser()
        self.assertTrue(parser.can_parse(tc_file))
    
    def test_cannot_parse_invalid_json(self):
        """Test JSON parser rejects invalid JSON"""
        invalid_file = Path(self.temp_dir) / "invalid.json"
        invalid_file.write_text('not json content')
        
        parser = JSONThreatParser()
        self.assertFalse(parser.can_parse(invalid_file))
    
    def test_parse_json_file(self):
        """Test parsing JSON file"""
        parser = JSONThreatParser()
        result = parser.parse(self.json_file)
        
        self.assertEqual(result['format'], 'json')
        self.assertIn('data', result)
        self.assertIn('threats', result['data'])


class TestYAMLParser(unittest.TestCase):
    """Test YAML parser"""
    
    def setUp(self):
        """Create temporary directory and test file"""
        self.temp_dir = tempfile.mkdtemp()
        self.yaml_file = Path(self.temp_dir) / "test.yaml"
        self.yaml_file.write_text('threats:\n  - id: T001\n    name: SQL Injection')
    
    def test_can_parse_yaml_file(self):
        """Test YAML parser recognizes YAML files"""
        parser = YAMLThreatParser()
        self.assertTrue(parser.can_parse(self.yaml_file))
    
    def test_can_parse_yml_file(self):
        """Test YAML parser recognizes .yml files"""
        yml_file = Path(self.temp_dir) / "test.yml"
        yml_file.write_text('threats: []')
        
        parser = YAMLThreatParser()
        self.assertTrue(parser.can_parse(yml_file))
    
    def test_parse_yaml_file(self):
        """Test parsing YAML file"""
        parser = YAMLThreatParser()
        result = parser.parse(self.yaml_file)
        
        self.assertEqual(result['format'], 'yaml')
        self.assertIn('data', result)


class TestMarkdownParser(unittest.TestCase):
    """Test Markdown parser"""
    
    def setUp(self):
        """Create temporary directory and test file"""
        self.temp_dir = tempfile.mkdtemp()
        self.md_file = Path(self.temp_dir) / "test.md"
        self.md_file.write_text('# Threats\n\n## High Threat: SQL Injection\n\nDescription here')
    
    def test_can_parse_markdown_file(self):
        """Test Markdown parser recognizes MD files"""
        parser = MarkdownThreatParser()
        self.assertTrue(parser.can_parse(self.md_file))
    
    def test_parse_markdown_file(self):
        """Test parsing Markdown file"""
        parser = MarkdownThreatParser()
        result = parser.parse(self.md_file)
        
        self.assertEqual(result['format'], 'markdown')
        self.assertIn('threats', result)
        self.assertGreater(len(result['threats']), 0)


class TestThreatComposerParser(unittest.TestCase):
    """Test ThreatComposer parser"""
    
    def setUp(self):
        """Create temporary directory and test file"""
        self.temp_dir = tempfile.mkdtemp()
        self.tc_file = Path(self.temp_dir) / "test.tc"
        self.tc_file.write_text('{"threats": [{"id": "T001"}], "architecture": {}}')
    
    def test_can_parse_threatcomposer_file(self):
        """Test ThreatComposer parser recognizes .tc files"""
        parser = ThreatComposerParser()
        self.assertTrue(parser.can_parse(self.tc_file))
    
    def test_parse_threatcomposer_file(self):
        """Test parsing ThreatComposer file"""
        parser = ThreatComposerParser()
        result = parser.parse(self.tc_file)
        
        self.assertEqual(result['format'], 'threatcomposer')
        self.assertIn('threats', result)
        self.assertIn('architecture', result)


class TestParserChain(unittest.TestCase):
    """Test ParserChain functionality"""
    
    def setUp(self):
        """Create temporary directory and test files"""
        self.temp_dir = tempfile.mkdtemp()
        self.json_file = Path(self.temp_dir) / "test.json"
        self.json_file.write_text('{"threats": [{"id": "T001"}]}')
    
    def test_register_parser(self):
        """Test registering parsers"""
        chain = ParserChain()
        parser = JSONThreatParser()
        
        chain.register(parser)
        self.assertEqual(len(chain.parsers), 1)
    
    def test_parser_priority(self):
        """Test parser priority ordering"""
        chain = ParserChain()
        
        parser1 = JSONThreatParser()
        parser2 = YAMLThreatParser()
        
        chain.register(parser1, priority=1)
        chain.register(parser2, priority=2)
        
        # Higher priority should be first
        self.assertEqual(chain.parsers[0][0], 2)
        self.assertEqual(chain.parsers[1][0], 1)
    
    def test_parse_with_chain(self):
        """Test parsing file through chain"""
        chain = ParserChain()
        chain.register(JSONThreatParser())
        
        result = chain.parse(self.json_file)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['format'], 'json')
    
    def test_fallback_returns_none(self):
        """Test fallback returns None for unsupported format"""
        chain = ParserChain()
        chain.register(JSONThreatParser())
        
        txt_file = Path(self.temp_dir) / "test.txt"
        txt_file.write_text("plain text")
        
        result = chain.parse(txt_file)
        self.assertIsNone(result)
    
    def test_get_compatible_parser(self):
        """Test getting compatible parser"""
        chain = ParserChain()
        json_parser = JSONThreatParser()
        chain.register(json_parser)
        
        parser = chain.get_compatible_parser(self.json_file)
        
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "json")
    
    def test_multiple_parsers_registered(self):
        """Test registering multiple parsers"""
        chain = ParserChain()
        chain.register(JSONThreatParser())
        chain.register(YAMLThreatParser())
        chain.register(MarkdownThreatParser())
        chain.register(ThreatComposerParser())
        
        self.assertEqual(len(chain.parsers), 4)


if __name__ == '__main__':
    unittest.main()
