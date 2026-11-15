#!/bin/bash
# Each test: $1=name $2=inputfile ; runs fullprove then verify, prints result
S=./node_modules/.bin/snarkjs
run() {
  name=$1; input=$2
  $S groth16 fullprove "$input" gatekeeper.wasm gatekeeper_final.zkey "proof-$name.json" "public-$name.json" >/tmp/fp-$name.log 2>&1
  fp=$?
  if [ $fp -eq 0 ]; then
    sz=$(wc -c < "proof-$name.json")
    $S groth16 verify verification_key.json "public-$name.json" "proof-$name.json" >/tmp/vf-$name.log 2>&1
    vf=$?
    vout=$(grep -o 'OK!' /tmp/vf-$name.log || echo "VERIFY-FAILED")
    echo "$name: fullProve=OK proof_bytes=$sz verify=$vout (exit $vf)"
  else
    err=$(grep -iE 'error|assert|fail' /tmp/fp-$name.log | head -2 | tr '\n' ' ')
    echo "$name: fullProve=FAILED (exit $fp) :: $err"
  fi
}
run "$@"
