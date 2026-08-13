# DDF Procurement Demo

This demonstration builds:

Alice → Planner → Procurement → Buyer

Authority narrows from:

- GBP 10,000 / `vendor/*`
- GBP 5,000 / `vendor/dell/*`
- GBP 2,000 / `vendor/dell/order/*`

A GBP 1,500 Dell purchase is allowed.

A GBP 20,000 purchase is denied.

Revoking the Procurement authority invalidates the Buyer descendant.
