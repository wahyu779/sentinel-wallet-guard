# SENTINEL — langkah registrasi (Wildcard track, zkVerify Agent Games)

> Untuk boss, dari HP/dashboard sendiri. JANGAN lewati langkah 1 dan 6 —
> secret HMAC cuma muncul SEKALI, dan server sekarang masih jalan di TEST
> HMAC (belum bisa ikut apa-apa sebelum secret asli di-inject).

## Keadaan sekarang (17:25 WIB 15 Nov 2026)

- Server SENTINEL HIDUP dan lolos harness penuh (PASS, 39/39):
  https://8080-001m7f910d340zs7j2hhtrs56wx.sbx.sandboxes-cloud.docker.com
- Server jalan di TEST HMAC — secret asli BELUM ada (baru dibuat saat
  registrasi, langkah 5).
- Repo GitHub publik BELUM dibuat — kode ada di
  `~/workspace/zkverify/wildcard/` (guard-server.js, guard-harness.js,
  decision.js, prove.js, kurier.js, circuit/, README.md). Kacung (parent)
  yang buatkan repo-nya via browser, seperti repo gatekeeper
  (wahyu779/proof-gatekeeper-agent). Nama yang disarankan:
  `wahyu779/sentinel-wallet-guard`.
- Sandbox wildcard (zkverify-wildcard-r1) kedaluwarsa 04:36 WIB 16 Nov —
  sebelum judging, server harus di-deploy ulang di sandbox fresh
  (20–21 Nov, Kacung yang kerjakan).

## Langkah 0 — repo publik (Kacung yang kerjakan, sebelum langkah 1)

Kacung buatkan repo GitHub publik baru `wahyu779/sentinel-wallet-guard`
dan push semua file dari `~/workspace/zkverify/wildcard/` (tanpa secret
apa pun — tidak ada secret di repo). Setelah push, URL repo-nya adalah:

```text
https://github.com/wahyu779/sentinel-wallet-guard
```

Kalau URL di atas belum bisa dibuka, repo belum dibuat — jangan lanjut
ke langkah 1 sebelum Kacung konfirmasi repo-nya sudah ada.

## Langkah 1 — buka pendaftaran agen

1. Buka https://agentgames.zkverify.io/ dari HP (login seperti biasa).
2. Buka **My Agents** → **Register agent** (atau **Build an agent** →
   register).
3. Isi form-nya persis seperti di bawah. PERHATIAN (pengalaman dari
   registrasi UNDERGROUND): kolom repo dan endpoint sudah ada awalan
   `https://` — ketik URL LENGKAP dengan `https://`, jangan cuma
   host-nya saja (host-only gagal: "Could not parse repository URL").

| Field | Isi |
|---|---|
| Agent name | `SENTINEL` |
| Repository URL | `https://github.com/wahyu779/sentinel-wallet-guard` |
| Endpoint URL | `https://8080-001m7f910d340zs7j2hhtrs56wx.sbx.sandboxes-cloud.docker.com` |
| Track / event | Centang **Wildcard SAJA**. JANGAN centang Proof Gatekeeper (UNDERGROUND sudah ikut di sana, satu akun cuma boleh satu agen per event otomatis) dan JANGAN centang Steal the VFY (pendaftarannya sudah tutup 13 Nov). |

4. Submit form-nya.

## Langkah 2 — simpan HMAC secret (PALING PENTING)

- Setelah submit, dashboard menampilkan **secret HMAC 32-byte persis
  SEKALI**. Langsung **copy + screenshot** saat itu juga.
- Secret ini KHUSUS untuk SENTINEL — beda dari secret UNDERGROUND.
  Jangan tukar-tukar.
- Jangan commit secret ini ke repo, jangan kirim lewat chat biasa.

## Langkah 3 — kirim secret ke Kacung (Secure Vault)

- Kacung kirim link capture (Secure Vault) untuk secret SENTINEL.
- Paste secret-nya di link itu (bukan di chat).
- Kacung inject secret itu ke server SENTINEL lewat endpoint inject
  (sama seperti HMAC UNDERGROUND), lalu restart server dengan
  `testMode=false` dan verifikasi ulang (preflight + harness).

## Langkah 4 — submit entry Wildcard

Setelah secret ter-inject dan server terverifikasi:

1. Di dashboard, buka **Your submissions** → **New submission**
   (Wildcard dan Creator Track dinilai terpisah dari game live; boleh
   submit lebih dari sekali).
2. Isi form submission:

| Field | Isi |
|---|---|
| Agent link | `https://github.com/wahyu779/sentinel-wallet-guard` |
| Public endpoint | `https://8080-001m7f910d340zs7j2hhtrs56wx.sbx.sandboxes-cloud.docker.com` |
| Use case | Wallet security guard — screens a crypto transaction against the user's own safety policy before signing, so a malicious approval or drainer cannot empty the wallet. Helps anyone who signs transactions. |
| Build context | Deterministic policy check (recipient, amount, balance, expiry, verification key) + Groth16 proof over the official gatekeeper circuit (VK already registered on zkVerify mainnet) + local proof verification before every response. Demo UI at GET /demo. Public screening API at POST /screen (rate limited 20/hour). Platform route POST / for HMAC-signed tasks. |
| zkVerify (optional) | Checkable claim: "This transaction's verdict is the correct one for the stated policy." Proof reference: any proof returned by POST /screen (verifiable locally against circuit/verification_key.json in the repo). |

3. Submit. Simpan bukti submit (screenshot / submission ID).

## Langkah 5 — sebelum judging (20–21 Nov, Kacung yang kerjakan)

- Sandbox wildcard sekarang kedaluwarsa 04:36 WIB 16 Nov — TIDAK akan
  hidup saat judging (setelah season tutup 21 Nov).
- Kacung buatkan sandbox fresh + deploy ulang server SENTINEL + inject
  secret asli + verifikasi (harness) pada 20–21 Nov, lalu boss update
  endpoint URL di dashboard kalau URL-nya berubah (URL baru =
  `https://8080-<id-sandbox-baru>.sbx.sandboxes-cloud.docker.com`).
- Repo + write-up tidak kedaluwarsa — itu bagian submission yang awet.

## Yang TIDAK perlu

- Kurier API key: OPSIONAL untuk Wildcard. Tanpa key, server tetap
  menjawab dengan proof + public signals yang terverifikasi lokal;
  `proof_tx` jatuh ke referensi request. (Berbeda dengan Gatekeeper
  yang butuh proof_tx on-chain untuk skor.)
- Biaya: pendaftaran + submit GRATIS. Jangan bayar apa pun.

## Kalau ada yang gagal

- Form repo/endpoint error "Could not parse repository URL": ketik URL
  lengkap dengan `https://` (lihat langkah 1).
- Secret hilang / tidak ke-copy: rotasi dari halaman settings agen
  (account-avatar dropdown → Account settings → agen SENTINEL) —
  secret lama langsung tidak berlaku, kirim secret baru ke Kacung
  lewat Secure Vault.
- Endpoint tidak bisa dijangkau saat registrasi: kabari Kacung —
  server mungkin perlu restart (sandbox masih hidup, tapi proses
  node bisa mati).
