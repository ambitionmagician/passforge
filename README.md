# PassForge

by Dr. Brent Allen Jensen

Generate memorable passphrases and strong passwords, with the entropy
math printed next to every secret so you can see how strong it is.

Passphrases are drawn from a built-in wordlist of common words using
the `secrets` module — a real cryptographic random source, never the
`random` module.

## Quickstart

```bash
python3 passforge.py                              # one 4-word passphrase
python3 passforge.py passphrase --words 6 --count 5
python3 passforge.py passphrase --capitalize --digit --separator .
python3 passforge.py password --length 24 --count 3
```

Example output:

```
doctor-church-work-wide (entropy: 43.59 bits)
```

## Options

Two modes: `passphrase` (the default when no mode is given) and
`password`.

Passphrase mode:

| Flag | Default | Meaning |
|---|---|---|
| `--words` | 4 | Words per passphrase |
| `--separator` | `-` | What goes between words |
| `--capitalize` | off | Capitalize the first letter |
| `--digit` | off | Append one random digit |
| `--count` | 1 | How many passphrases to generate |

Password mode:

| Flag | Default | Meaning |
|---|---|---|
| `--length` | 20 | Password length |
| `--count` | 1 | How many passwords to generate |

## Requirements

- Python 3.10+, standard library only

## Notes

- Entropy estimates assume the attacker knows the scheme and the
  wordlist — the honest way to count. Length is what buys safety.
- Nothing is stored or transmitted; secrets exist only on your screen.
  Generate them on a machine you trust.

## Support this work

If this tool saved you time or taught you something, donations keep the work going:

- BTC: 15McijPo79Zx58NGyEf2PvaPtGqGmpztWn
- ETH: 0x8C25164E9234E6A30b8E44485B79c5cE8419cF2B

## License

MIT — see [LICENSE](LICENSE).
