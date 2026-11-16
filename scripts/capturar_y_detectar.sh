#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
lab_dir="$repo_dir/lab"
snort_bin="$lab_dir/tools/usr/sbin/snort"
daq_dir="$lab_dir/tools/usr/lib/aarch64-linux-gnu/daq3"
lib_dir="$lab_dir/tools/usr/lib/aarch64-linux-gnu"

for tool in dumpcap nmap; do
  command -v "$tool" >/dev/null || { echo "Falta la herramienta: $tool" >&2; exit 1; }
done
test -x "$snort_bin" || { echo 'Preparar primero Snort en lab/tools según docs/LABORATORIO.md' >&2; exit 1; }
test -d "$daq_dir" || { echo 'Falta el directorio DAQ de ARM64; revisar la arquitectura y la guía.' >&2; exit 1; }

cd "$lab_dir"
capture_pid=''
cleanup() {
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

dumpcap -i lo -a duration:10 -w nmap_capture.pcap > capture.log 2>&1 &
capture_pid=$!
sleep 1
kill -0 "$capture_pid" 2>/dev/null || { cat capture.log >&2; exit 1; }
nmap -sT -p 1-100 -T4 127.0.0.1 -oN nmap_ids.txt
wait "$capture_pid"
capture_pid=''

LD_LIBRARY_PATH="$lib_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$snort_bin" --daq-dir "$daq_dir" --daq pcap \
  -r nmap_capture.pcap -R "$repo_dir/reglas/local.rules" \
  -A alert_fast -k none > snort_resultados.txt 2>&1

cat capture.log
grep -E 'LAB SYN scan|analyzed:|alerts:|logged:' snort_resultados.txt || true
echo 'Resultado de detección sobre captura; no valida bloqueo IPS inline.'
