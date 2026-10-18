#!/usr/bin/env bash
# 릴레이 VM 에서 실행: 사설 CA / 릴레이 서버 인증서 / 분석 회차별 에이전트 인증서 생성
#
#   ./gen-certs.sh ca                          # 최초 1회: 사설 CA
#   ./gen-certs.sh server <relay-ip>           # 릴레이 서버 인증서 (+ 핀 출력)
#   ./gen-certs.sh agent  <session-id> [days]  # 분석 회차마다: 에이전트 인증서 (기본 1일)
#
# CA 개인키(ca.key)는 릴레이 VM 밖(오프라인)에 보관하는 것을 권장.
# 게스트 VM 에는 ca.pem, agent-<sid>.pem, agent-<sid>.key 만 복사한다.
set -euo pipefail
OUT="${OUT_DIR:-./pki}"
mkdir -p "$OUT"
umask 077

case "${1:-}" in
  ca)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$OUT/ca.key" -out "$OUT/ca.pem" -days 825 \
      -subj "/CN=edr-lite-private-ca" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "CA 생성: $OUT/ca.pem"
    ;;
  server)
    IP="${2:?relay IP 필요}"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$OUT/relay.key" -out "$OUT/relay.csr" -subj "/CN=edr-relay"
    openssl x509 -req -in "$OUT/relay.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
      -CAcreateserial -out "$OUT/relay.pem" -days 397 \
      -extfile <(printf "subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE" "$IP")
    rm -f "$OUT/relay.csr"
    PIN=$(openssl x509 -in "$OUT/relay.pem" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
    echo "릴레이 인증서: $OUT/relay.pem"
    echo "agent.toml 의 server_cert_sha256 = \"$PIN\""
    ;;
  agent)
    SID="${2:?session-id 필요}"
    DAYS="${3:-1}"
    [[ "$SID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "session-id 형식 오류"; exit 1; }
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$OUT/agent-$SID.key" -out "$OUT/agent-$SID.csr" -subj "/CN=$SID"
    openssl x509 -req -in "$OUT/agent-$SID.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
      -CAcreateserial -out "$OUT/agent-$SID.pem" -days "$DAYS" \
      -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE")
    rm -f "$OUT/agent-$SID.csr"
    echo "에이전트 인증서 (CN=$SID, ${DAYS}일): $OUT/agent-$SID.pem / .key"
    ;;
  *)
    sed -n '2,8p' "$0"; exit 1;;
esac
