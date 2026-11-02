#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: ./check_kat_hash.sh [options] [variant ...]

By default this script first runs each implementation's run_kat_sig.sh for the
selected variants, then compares Optimized, Reference, and Test_Vectors KAT
outputs by SHA256.

Options:
  --run-kats        Run implementation KATs before hashing (default).
  --hash-only       Only hash already-generated outputs.
  --no-run-kats     Alias for --hash-only.
  --variant NAME    Check one variant. May be repeated.
  -h, --help        Show this help.

Environment:
  CHECK_KAT_HASH_RUN_KATS=0   Default to --hash-only.
EOF
}

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

pick_test_vector() {
  local candidate
  for candidate in "$@"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

run_variant_kat() {
  local impl_label="$1"
  local impl_root="$2"
  local variant="$3"
  local variant_dir="${impl_root}/${variant}"
  local kat_script="${variant_dir}/run_kat_sig.sh"
  local kat_rc

  echo "=== ${variant} (${impl_label} KAT generation) ==="
  if [[ ! -d "${variant_dir}" ]]; then
    echo "[ERROR] Directory not found: ${variant_dir}"
    echo
    return 1
  fi
  if [[ ! -f "${kat_script}" ]]; then
    echo "[ERROR] KAT runner not found: ${kat_script}"
    echo
    return 1
  fi

  set +e
  bash "${kat_script}"
  kat_rc=$?
  set -e

  if [[ "${kat_rc}" -ne 0 ]]; then
    echo "[FAIL] ${impl_label} KAT generation failed for ${variant} (rc=${kat_rc})."
    echo
    return "${kat_rc}"
  fi

  echo "[PASS] ${impl_label} KAT generation completed for ${variant}."
  echo
  return 0
}

check_pair() {
  local title="$1"
  local file_a="$2"
  local label_a="$3"
  local file_b="$4"
  local label_b="$5"

  echo "=== ${title} ==="
  for f in "$file_a" "$file_b"; do
    if [[ ! -f "$f" ]]; then
      echo "[ERROR] File not found: $f"
      return 1
    fi
  done

  local hash_a hash_b
  hash_a="$(hash_file "$file_a")"
  hash_b="$(hash_file "$file_b")"

  echo "${label_a} SHA256: ${hash_a}"
  echo "${label_b} SHA256: ${hash_b}"
  if [[ "${hash_a}" == "${hash_b}" ]]; then
    echo "[PASS] ${label_a} == ${label_b}"
  else
    echo "[FAIL] ${label_a} != ${label_b}"
    return 1
  fi
  echo
  return 0
}

check_triplet() {
  local title="$1"
  local file_a="$2"
  local label_a="$3"
  local file_b="$4"
  local label_b="$5"
  local file_c="$6"
  local label_c="$7"

  echo "=== ${title} ==="
  for f in "$file_a" "$file_b" "$file_c"; do
    if [[ ! -f "$f" ]]; then
      echo "[ERROR] File not found: $f"
      return 1
    fi
  done

  local hash_a hash_b hash_c
  hash_a="$(hash_file "$file_a")"
  hash_b="$(hash_file "$file_b")"
  hash_c="$(hash_file "$file_c")"

  echo "${label_a} SHA256: ${hash_a}"
  echo "${label_b} SHA256: ${hash_b}"
  echo "${label_c} SHA256: ${hash_c}"

  local ok=0
  if [[ "${hash_a}" == "${hash_b}" ]]; then
    echo "[PASS] ${label_a} == ${label_b}"
  else
    echo "[FAIL] ${label_a} != ${label_b}"
    ok=1
  fi

  if [[ "${hash_a}" == "${hash_c}" ]]; then
    echo "[PASS] ${label_a} == ${label_c}"
  else
    echo "[FAIL] ${label_a} != ${label_c}"
    ok=1
  fi

  if [[ "${hash_b}" == "${hash_c}" ]]; then
    echo "[PASS] ${label_b} == ${label_c}"
  else
    echo "[FAIL] ${label_b} != ${label_c}"
    ok=1
  fi
  echo

  return "${ok}"
}

rc=0

BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OPT_DIR="${SCRIPT_DIR}/Optimized_Implementation"
REF_DIR="${SCRIPT_DIR}/Reference_Implementation"
TV_DIR="${BASE_DIR}/Test_Vectors"

if [[ ! -d "${OPT_DIR}" || ! -d "${REF_DIR}" || ! -d "${TV_DIR}" ]]; then
  echo "[ERROR] Invalid Chinith directory layout."
  echo "        expected this script at: ${BASE_DIR}/Implementations/check_kat_hash.sh"
  echo "        expected Optimized dir:  ${OPT_DIR}"
  echo "        expected Reference dir:  ${REF_DIR}"
  echo "        expected Test_Vectors:   ${TV_DIR}"
  exit 1
fi

run_kats="${CHECK_KAT_HASH_RUN_KATS:-1}"
case "${run_kats}" in
  1|yes|true|on) run_kats=1 ;;
  0|no|false|off) run_kats=0 ;;
  *)
    echo "[ERROR] CHECK_KAT_HASH_RUN_KATS must be 0 or 1."
    exit 2
    ;;
esac

check_variant() {
  local variant="$1"
  local opt1="$2"
  local opt2="$3"
  local ref1="$4"
  local ref2="$5"
  local tv1="$6"
  local tv2="$7"

  local opt_file ref_file tv_file
  tv_file=""
  opt_file="$(pick_test_vector "${opt1}" "${opt2}" || true)"
  ref_file="$(pick_test_vector "${ref1}" "${ref2}" || true)"
  if [[ -n "${tv1}" || -n "${tv2}" ]]; then
    tv_file="$(pick_test_vector "${tv1}" "${tv2}" || true)"
  fi

  if [[ -z "${opt_file}" ]]; then
    echo "[ERROR] Optimized output for ${variant} not found."
    echo "        tried: ${opt1} | ${opt2}"
    rc=1
    return
  fi
  if [[ -z "${ref_file}" ]]; then
    echo "[ERROR] Reference output for ${variant} not found."
    echo "        tried: ${ref1} | ${ref2}"
    rc=1
    return
  fi
  if [[ -n "${tv_file}" ]]; then
    check_triplet \
      "${variant} (Opt/Ref/Test_Vectors)" \
      "${opt_file}" "Optimized" \
      "${ref_file}" "Reference" \
      "${tv_file}" "Test_Vectors" || rc=1
  else
    if [[ -n "${tv1}" || -n "${tv2}" ]]; then
      echo "[WARN] Test_Vectors for ${variant} not found; comparing Opt vs Ref only."
      echo "       tried: ${tv1} | ${tv2}"
    fi
    check_pair \
      "${variant} (Opt/Ref)" \
      "${opt_file}" "Optimized" \
      "${ref_file}" "Reference" || rc=1
  fi
}

variants=(
  sm4th_d3_128s_loose
  sm4th_d3_128f_loose
  sm4th_em_d2_128s_loose
  sm4th_em_d2_128f_loose
  sm4th_d3_128s_tight
  sm4th_d3_128f_tight
  sm4th_em_d2_128s_tight
  sm4th_em_d2_128f_tight
  ublockith_d3_256s
  ublockith_d3_256f
  ublockith_em_d3_256s
  ublockith_em_d3_256f
  vistrutith_d3_512f
  vistrutith_d3_512s
)

selected_variants=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-kats)
      run_kats=1
      ;;
    --hash-only|--no-run-kats)
      run_kats=0
      ;;
    --variant)
      shift
      if [[ "$#" -eq 0 ]]; then
        echo "[ERROR] --variant requires a variant name."
        exit 2
      fi
      selected_variants+=("$1")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        selected_variants+=("$1")
        shift
      done
      break
      ;;
    -*)
      echo "[ERROR] Unknown option: $1"
      usage
      exit 2
      ;;
    *)
      selected_variants+=("$1")
      ;;
  esac
  shift
done

variants_to_check=()
if [[ "${#selected_variants[@]}" -eq 0 ]]; then
  variants_to_check=("${variants[@]}")
else
  for selected in "${selected_variants[@]}"; do
    found=0
    for variant in "${variants[@]}"; do
      if [[ "${variant}" == "${selected}" ]]; then
        found=1
        break
      fi
    done
    if [[ "${found}" -eq 0 ]]; then
      echo "[ERROR] Unknown variant: ${selected}"
      echo "Known variants:"
      for variant in "${variants[@]}"; do
        echo "  ${variant}"
      done
      exit 2
    fi
    variants_to_check+=("${selected}")
  done
fi

if [[ "${run_kats}" -eq 1 ]]; then
  kat_rc=0
  echo "[INFO] Running implementation KATs before hash checks."
  echo "[INFO] Set CHECK_KAT_HASH_RUN_KATS=0 or pass --hash-only to skip this step."
  echo
  for variant in "${variants_to_check[@]}"; do
    run_variant_kat "Optimized" "${OPT_DIR}" "${variant}" || kat_rc=1
    run_variant_kat "Reference" "${REF_DIR}" "${variant}" || kat_rc=1
  done
  if [[ "${kat_rc}" -ne 0 ]]; then
    echo "[FAIL] Some implementation KAT runs failed; not comparing hashes against possibly stale outputs."
    exit "${kat_rc}"
  fi
else
  echo "[INFO] Skipping implementation KAT generation; hashing existing outputs only."
  echo
fi

for variant in "${variants_to_check[@]}"; do
  tv1="${TV_DIR}/KAT_SIG_${variant}.txt"
  tv2=""
  check_variant \
    "${variant}" \
    "${OPT_DIR}/${variant}/output/KAT_SIG_${variant}.txt" \
    "" \
    "${REF_DIR}/${variant}/output/KAT_SIG_${variant}.txt" \
    "" \
    "${tv1}" \
    "${tv2}"
done

if [[ "${rc}" -eq 0 ]]; then
  echo "[PASS] All requested KAT hash checks passed."
else
  echo "[FAIL] Some KAT hash checks failed."
fi
exit "${rc}"
