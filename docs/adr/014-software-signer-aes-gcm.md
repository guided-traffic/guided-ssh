# ADR-014: Software-Signer mit AES-256-GCM-verschlüsselten CA-Keys

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 2 braucht eine Ablage der Ed25519-CA-Private-Keys, die ohne KMS/HSM
auskommt (das folgt in Phase 10 über dasselbe `Signer`-Interface), aber Keys
nicht im Klartext in der Datenbank liegen lässt. Der Plan nennt als Kandidaten
age oder AES-GCM mit einem Master-Key aus einem Kubernetes-Secret.

## Entscheidung

AES-256-GCM aus der Go-Standardbibliothek (`crypto/aes` + `crypto/cipher`),
kein age. Der Private Key wird im OpenSSH-PEM-Format serialisiert und als
`nonce || ciphertext` in `ca_keys.encrypted_private_key` abgelegt. Der
32-Byte-Master-Key kommt Base64-kodiert aus der Umgebungsvariable
`GSSH_CA_MASTER_KEY` (im Kubernetes-Deployment aus einem Secret).

## Konsequenzen

- Keine zusätzliche Abhängigkeit; GCM liefert Vertraulichkeit und Integrität
  (manipulierte oder mit falschem Key entschlüsselte Daten schlagen fehl).
- age hätte gegenüber direktem AES-GCM hier keinen Mehrwert: es kapselt
  letztlich dieselbe Primitive, adressiert aber Datei-/Empfänger-Szenarien.
- Master-Key-Rotation erfordert Umschlüsseln der `ca_keys`-Einträge; bei den
  wenigen Zeilen ist das ein einfacher, später ergänzbarer Admin-Befehl.
- Kompromittierung des Master-Keys plus DB-Zugriff gibt die CA-Keys preis —
  akzeptiert fürs MVP, Härtung via PKCS#11/KMS in Phase 10
  (Bedrohungsmodell: `docs/bedrohungsmodell.md`).
