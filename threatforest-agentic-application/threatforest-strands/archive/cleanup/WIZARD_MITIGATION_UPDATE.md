# Wizard Mitigation Mode - Folder Selection Update

## ✅ Update Complete

The mitigation mapping mode in the wizard now allows users to select custom input and output directories.

## New Features

### 1. **Input Directory Selection**
Users can now specify which folder contains the attack trees to process:
- Default: `output/enriched_v2`
- Custom: Any path with `.md` files

### 2. **Output Directory Selection**
Users can specify where to save the mitigated attack trees:
- Default: `output/mitigated`
- Custom: Any writable path

## Usage Example

```bash
python3 src/wizard.py
# Select option 3

📁 Select attack trees directory:
   Default: output/enriched_v2
Enter path to attack trees (or press Enter for default): my_custom_trees

📁 Select output directory:
   Default: output/mitigated
Enter output path (or press Enter for default): my_output
```

## Workflow

```
User selects option 3 (Mitigation Mapping)
    ↓
Wizard prompts for input directory
    • Shows default path
    • User can enter custom path or press Enter
    ↓
Wizard finds .md files in directory
    ↓
Wizard prompts for output directory
    • Shows default path
    • User can enter custom path or press Enter
    ↓
Processes all attack trees
    ↓
Shows summary with both input and output paths
```

## Benefits

- ✅ **Flexibility**: Process attack trees from any location
- ✅ **Organization**: Save outputs to custom directories
- ✅ **Batch Processing**: Process multiple sets of attack trees
- ✅ **Testing**: Use separate directories for testing

## Example Scenarios

### Scenario 1: Default Paths
```
Input: output/enriched_v2 (press Enter)
Output: output/mitigated (press Enter)
```

### Scenario 2: Custom Input
```
Input: /path/to/my/attack_trees
Output: output/mitigated (press Enter)
```

### Scenario 3: Both Custom
```
Input: project_a/enriched
Output: project_a/mitigated
```

## Validation

The wizard validates:
- ✅ Input directory exists
- ✅ Input directory contains `.md` files
- ✅ STIX bundle exists
- ✅ Output directory is created if needed

## Summary Display

The completion summary now shows both directories:

```
📁 Input Directory: output/enriched_v2
📁 Output Directory: output/mitigated
```

This helps users confirm which directories were processed.
