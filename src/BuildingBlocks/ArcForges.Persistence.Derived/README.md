# ArcForges.Persistence.Derived

This package provides owner-neutral contracts for data that can be deleted and
rebuilt from canonical owner data, plus a storage-pressure model and an eviction
policy restricted to registered derived stores.

`DerivedStore` represents one independently deletable and rebuildable projection.
Its canonical input is exposed through a stable read-only snapshot; derived records
retain the exact source identity and revision together with the pipeline version.
`StoragePressureState` carries caller-classified pressure, available space, the
durability reserve, canonical usage and registered derived-store estimates. It does
not choose product-specific pressure thresholds.

`StoragePressureEvictionPolicy` plans and deletes only the registered derived
stores. It never owns, writes or evicts canonical product data. Consumers retain
ownership of their own data paths, schemas, canonical records, DTOs, derived-store
implementations and pressure decisions; this package does not centralize product
data ownership.

The package contains mechanism contracts, not a product database or a configured
derived-store implementation. Offline tests exercise rebuild and eviction with
test-owned canonical snapshots and stores.
