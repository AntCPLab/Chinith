#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

make NDEBUG=1 KAT_SIG
./KAT_SIG

algo="$(awk -F'"' '/#define[[:space:]]+ALGORITHM_INSTANCE/{print $2; exit}' sm4th_d3_128f_tight_AlgorithmInstance.h)"
kat_txt="output/KAT_SIG_${algo}.txt"
if [[ ! -f "${kat_txt}" ]]; then
  echo "ERROR: ${kat_txt} not found" >&2
  exit 1
fi

echo "KAT saved to ${kat_txt}"
