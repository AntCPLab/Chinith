#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

arch="$(uname -m)"
is_hygon_cpu() {
  [[ -r /proc/cpuinfo ]] && grep -qiE 'HygonGenuine|vendor_id[[:space:]]*:[[:space:]]*Hygon' /proc/cpuinfo
}

hygon_mode="${HYGON_SM4_KAT:-auto}"
use_hygon_sm4=0
case "${hygon_mode}" in
  1|yes|true) use_hygon_sm4=1 ;;
  0|no|false) use_hygon_sm4=0 ;;
  auto)
    if [[ "${arch}" == "x86_64" ]] && is_hygon_cpu; then
      use_hygon_sm4=1
    fi
    ;;
  *)
    echo "ERROR: HYGON_SM4_KAT must be auto, 1, or 0" >&2
    exit 2
    ;;
esac

if [[ "${arch}" != "x86_64" && "${arch}" != "i386" && "${arch}" != "i686" ]]; then
  echo "[KAT_SIG] non-x86 detected (${arch}); running Opt in portable mode (PRG_ACCE=0 FIELD_PCLMUL=0)."
  make NDEBUG=1 PRG_ACCE=0 FIELD_PCLMUL=0 KAT_SIG
elif [[ "${use_hygon_sm4}" -eq 1 ]]; then
  if [[ "${arch}" != "x86_64" ]]; then
    echo "ERROR: Hygon CIS SM4 KAT requires x86_64, got ${arch}" >&2
    exit 2
  fi
  echo "[KAT_SIG] Hygon SM4 requested/detected; probing Hygon CIS SM4 before KAT_SIG."
  make NDEBUG=1 PRG_ACCE=0 HYGON_SM4_ACCE=1 hygon_cis_sm4_probe
  set +e
  ./hygon_cis_sm4_probe
  probe_rc=$?
  set -e
  if [[ "${probe_rc}" -ne 0 ]]; then
    echo "ERROR: Hygon CIS SM4 probe failed with status ${probe_rc}; not running KAT_SIG fallback." >&2
    exit "${probe_rc}"
  fi
  make NDEBUG=1 PRG_ACCE=0 HYGON_SM4_ACCE=1 KAT_SIG
else
  echo "[KAT_SIG] x86 detected (${arch}); running default optimized KAT_SIG path."
  make NDEBUG=1 KAT_SIG
fi
./KAT_SIG

algo="$(awk -F'"' '/#define[[:space:]]+ALGORITHM_INSTANCE/{print $2; exit}' sm4th_d3_128f_loose_AlgorithmInstance.h)"
kat_txt="output/KAT_SIG_${algo}.txt"
if [[ ! -f "${kat_txt}" ]]; then
  echo "ERROR: ${kat_txt} not found" >&2
  exit 1
fi

echo "KAT saved to ${kat_txt}"
