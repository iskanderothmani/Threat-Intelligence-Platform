# Threat Intelligence Platform

A local threat-intelligence triage tool that normalizes indicators, scores risk, and flags suspicious IPs, domains, URLs, and file hashes using transparent demo rules.

## Problem and solution
Security teams need repeatable triage that is explainable, auditable, and safe to test. This repository provides a small local-first prototype with transparent rules and synthetic examples.

## Features
- Normalize and validate IPv4 addresses, domains, URLs, and SHA-256 hashes
- Apply explainable heuristic scoring and severity labels
- Import/export JSON or CSV-friendly records
- Use synthetic examples only; no external lookups or network calls by default

## Requirements
- Python 3.10+
- Standard library only

## Quick start
```bash
python app.py
```
Some tools accept a file or directory path; run `python app.py` without arguments to see usage where applicable.

## Safety and scope
This is an educational proof of concept, not a production security control. Test only with systems, files, and data you own or are authorized to assess. Do not commit credentials, personal information, real incident logs, or confidential company data. Findings are heuristic and require human validation.

## Roadmap
- Add automated unit tests and CI
- Add structured logging and configuration
- Add signed sample datasets and richer reporting
- Validate against documented test cases before production use

## License
MIT
