# ThreatForest UI - Enrichment & Mitigation Implementation

## Summary

Added two new workflow modes to the React UI:
1. **Enrich** - Add TTC technique mappings to existing attack trees
2. **Mitigate** - Add mitigation recommendations to enriched attack trees

## Changes Made

### 1. New Components

#### `ui/src/components/ModeSelector.tsx`
- Interactive mode selection component
- Allows users to choose between:
  - Full Analysis (generate attack trees)
  - Enrich (add TTC mappings)
  - Mitigate (add mitigations)

### 2. Updated Components

#### `ui/src/components/WelcomeScreen.tsx`
- Added mode selection state
- Integrated ModeSelector component
- Routes to appropriate workflow based on selection

#### `ui/src/components/App.tsx`
- Added `Mode` type: `'full' | 'enrich' | 'mitigate'`
- Updated `AppState` to include mode
- Added `executeEnrichmentOrMitigation()` function
- Routes enrich/mitigate modes directly to execution (skips config)

### 3. Python Bridge Extensions

#### `ui/src/utils/pythonBridge.ts`
Added two new methods:

**`enrichAttackTrees(inputDir, outputDir)`**
- Calls `TTCMatcher` and `AttackTreeEnricher` from `src/modules/ttc_mappings`
- Processes attack trees in input directory
- Adds TTC technique IDs to mermaid diagrams
- Outputs enriched files to output directory

**`addMitigations(inputDir, outputDir)`**
- Calls `MitigationMapper` from `src/modules/ttc_mappings`
- Processes enriched attack trees
- Adds mitigation recommendations from STIX bundle
- Outputs mitigated files to output directory

## Usage Flow

### Full Analysis Mode (Default)
```
Welcome → Mode Selection → Config → Progress → Summary
```

### Enrich Mode
```
Welcome → Mode Selection → Progress (enrichment) → Summary
```
- Reads from: `output/attack_trees/`
- Writes to: `output/enriched/`

### Mitigate Mode
```
Welcome → Mode Selection → Progress (mitigation) → Summary
```
- Reads from: `output/enriched/`
- Writes to: `output/mitigated/`

## Testing

Build the UI:
```bash
cd ui
npm run build:cli
```

Run ThreatForest:
```bash
python threatforest.py
```

Then:
1. Type 'start' or 's'
2. Select mode (1, 2, or 3)
3. Follow prompts

## Dependencies

### Python Modules Required
- `src/modules/ttc_mappings/matcher.py` - TTCMatcher class
- `src/modules/ttc_mappings/enricher.py` - AttackTreeEnricher class
- `src/modules/ttc_mappings/mitigation_mapper.py` - MitigationMapper class

### Data Files Required
- `src/modules/ttc_mappings/data/ttc_embeddings.json` - TTC embeddings
- `stix-data/aaf-bundle.json` - STIX bundle for mitigations

## Next Steps

Potential enhancements:
1. Add directory selection UI for enrich/mitigate modes
2. Add progress indicators for batch processing
3. Add validation to check if required files exist
4. Add summary statistics to completion screen
5. Add option to chain modes (full → enrich → mitigate)
