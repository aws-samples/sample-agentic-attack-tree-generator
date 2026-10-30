# TTP quality evaluation

This directory contains the deterministic, offline quality gate for attack-step
to technique mappings. It does not invoke models, the ML service, or the network.

## Run

```sh
npm run evaluate:ttp -- \
  --dataset src/evaluation/__fixtures__/ttp-quality-v1.json \
  --precision-threshold 0.70 \
  --top-k 3 \
  --calibration-bins 10
```

Use `--json` for CI artifacts. The process exits non-zero when validation fails
or accepted precision is below the threshold. Coverage is deliberately not a
gate: the mapper may abstain when evidence is insufficient. An all-abstention
run cannot pass because accepted precision is undefined.

## Dataset v1.0.0

JSON datasets use one envelope with `records`. JSONL datasets put one
`type: "metadata"` object first, followed by `type: "record"` objects. Blank
lines and lines beginning with `#` are allowed in JSONL.

Every record contains:

- a unique `id`, a `sourceId`, and `split: "test"`
- the attack-step text and one or more human-accepted `acceptedTechniqueIds`
- an explicit `abstained` decision
- ranked predictions with `techniqueId`, `modelConfidence`, and `similarity`

Prediction ranks must be consecutive from one. Abstained records require a
reason and no predictions. Non-abstained records require at least one
prediction and no abstention reason.

`provenance.heldOut` must be `true`. Populate the three training-data arrays
from the model/matcher training manifest. The validator rejects evaluation
record IDs, source IDs, or normalized attack-step SHA-256 hashes that overlap
that manifest. It also rejects duplicate record IDs, normalized attack-step
text, accepted labels, candidate labels, or provenance IDs. This catches
accidental weighting and known train/test leakage; it cannot detect training
examples omitted from the manifest.

Canonical technique IDs are accepted for:

- MITRE ATT&CK: `T1190`, `T1098.001`
- MITRE ATLAS: `AML.T0043`, `AML.T0000.001`
- Wiz cloud techniques: lowercase slugs such as `container-escape`

## Metrics

- **Accepted precision**: accepted top-1 mappings divided by non-abstained
  mappings. This is the only gated metric.
- **Coverage**: non-abstained records divided by all records.
- **Abstention rate**: abstained records divided by all records.
- **Top-k recall**: accepted labels found in the first `k` candidates divided
  by all accepted labels. Abstentions therefore reduce recall.
- **Expected calibration error**: confidence-weighted absolute difference
  between mean top-1 confidence and top-1 accuracy across equal-width bins.
  It is calculated only for non-abstained mappings.

Keep datasets immutable once used for a release. Add a new dataset ID and file
when labels, examples, or the schema change so CI results remain reproducible.
