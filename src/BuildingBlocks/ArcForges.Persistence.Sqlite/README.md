# ArcForges.Persistence.Sqlite

PLT.01 implements the shared local store mechanism: one authorized atomic write path,
owner-bound version tokens, durable command receipts, payload/origin co-commit and outbox.
PLT.02 supplies the journal and PLT.04 supplies ordered schema migrations through restricted
internal transaction contexts. Products retain their own files and schemas.

This in-progress producer is not a completed persistence capability until its retained
review, offline real-file tests, publication and task receipts are recorded.
