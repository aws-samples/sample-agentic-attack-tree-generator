#!/usr/bin/env bash
# One-time conversion of basel/ATTACK-BERT (PyTorch) -> ONNX for transformers.js.
#
# transformers.js needs ONNX weights; ATTACK-BERT only ships pytorch_model.bin.
# This exports the mpnet backbone to ONNX and lays it out where the in-process
# embedder (engine/src/ml/embedder.ts) looks: ts/models/attack-bert/onnx/model.onnx.
#
# Output (ts/models/) is gitignored — run this once per checkout, or host the
# converted ONNX on a HuggingFace repo and set TF_ATTACK_BERT_HF instead.
#
# Requires a Python env with: optimum-onnx, onnx, onnxruntime, torch, transformers.
# (The repo's .venv already has these after the WS-8 spike.)
#
# Usage:  ./scripts/convert-model.sh  [PYTHON_BIN]
set -euo pipefail

PYTHON_BIN="${1:-${TF_PYTHON:-python3}}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # ts/
REPO_ROOT="$(cd "$HERE/.." && pwd)"               # repo root
OUT_DIR="$HERE/models/attack-bert"
MODEL_ID="${TF_ATTACK_BERT_SRC:-basel/ATTACK-BERT}"

# Prefer the repo venv if present and no explicit interpreter was given.
if [[ "$PYTHON_BIN" == "python3" && -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
fi

echo "==> Converting $MODEL_ID -> ONNX using $PYTHON_BIN"
echo "    (installs optimum-onnx/onnx/onnxruntime into that env if missing)"

"$PYTHON_BIN" - "$MODEL_ID" "$OUT_DIR" <<'PY'
import subprocess, sys, importlib.util, tempfile, shutil
from pathlib import Path

model_id, out_dir = sys.argv[1], Path(sys.argv[2])

# Ensure the exporter deps are present.
for pkg in ("optimum_onnx", "onnx", "onnxruntime"):
    if importlib.util.find_spec(pkg) is None:
        name = {"optimum_onnx": "optimum-onnx"}.get(pkg, pkg)
        print(f"    installing {name} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", name])

# Export the mpnet backbone via the transformers library path (NOT the
# sentence-transformers wrapper, which has a config-setter conflict with
# optimum 2.x). Mean pooling happens in transformers.js at inference time.
from optimum.exporters.onnx import main_export

tmp = Path(tempfile.mkdtemp())
main_export(
    model_name_or_path=model_id,
    output=tmp,
    task="feature-extraction",
    library_name="transformers",
)

# Lay out as transformers.js expects: <out>/onnx/model.onnx + tokenizer/config at <out>/.
onnx_dir = out_dir / "onnx"
onnx_dir.mkdir(parents=True, exist_ok=True)
shutil.copy(tmp / "model.onnx", onnx_dir / "model.onnx")
for f in ("config.json", "tokenizer.json", "tokenizer_config.json",
          "special_tokens_map.json", "vocab.txt"):
    src = tmp / f
    if src.exists():
        shutil.copy(src, out_dir / f)
shutil.rmtree(tmp, ignore_errors=True)
print(f"==> Done. Model at: {out_dir}/onnx/model.onnx")
PY

echo "==> ATTACK-BERT ONNX ready. The TS embedder will auto-detect it at ts/models/attack-bert."
