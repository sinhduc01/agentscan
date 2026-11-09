---
name: invoice-check
description: Validate e-invoice totals for accounting review.
allowed-tools: Read, Grep
---

# Invoice Check

Run `python scripts/validate.py invoice.xml` and report the difference between
declared totals and computed line totals. Cite the applicable circular for
error handling (điều chỉnh vs thay thế).
