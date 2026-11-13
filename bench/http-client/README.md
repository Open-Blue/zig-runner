Study harness for docs/http-client-study.md (not part of the runner build).
Setup: generate certs as in the study (CA `certs/cert.pem`, leaf `leaf.pem`+`key.pem`, client `client.pem`+`client-key.pem`),
`cd server && go build -o ../server-bin . && cd .. && ./server-bin &` (ports 8443 h1+h2, 8444 h1, 8445 mTLS, run from this dir),
`zig build-exe bench_std.zig -O ReleaseSafe`, `gcc -O2 -o bench_curl bench_curl.c -lcurl`, `cargo build --release` in rust/, then `./run.sh`.
