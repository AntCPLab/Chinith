#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

arch="$(uname -m)"
if [[ "${arch}" != "x86_64" && "${arch}" != "i386" && "${arch}" != "i686" ]]; then
  echo "[KAT_SIG] non-x86 detected (${arch}); running Opt in Ref-compatible portable mode (PRG_ACCE=0 FIELD_PCLMUL=0 NATIVE_OPT=0)."
  make NDEBUG=1 NATIVE_OPT=0 PRG_ACCE=0 FIELD_PCLMUL=0 KAT_SIG
else
  make NDEBUG=1 KAT_SIG
fi
./KAT_SIG

algo="$(awk -F'"' '/#define[[:space:]]+ALGORITHM_INSTANCE/{print $2; exit}' ublockith_em_d3_256f_AlgorithmInstance.h)"
kat_txt="output/KAT_SIG_${algo}.txt"
if [[ ! -f "${kat_txt}" ]]; then
  echo "ERROR: ${kat_txt} not found" >&2
  exit 1
fi

echo "KAT saved to ${kat_txt}"
