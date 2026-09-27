# ArcForges.Foundation

Shared storage-free Foundation primitives. Exact UUID, integer, decimal and rational
wire values remain owned by the pinned `ArcForges.Contracts.Foundation` package;
this assembly adds generation and behavior, not a duplicate protobuf schema.

`IdentityGeneration` creates new nonzero random UUIDs using the Contracts domain
types. Owners persist installation/device/workspace identities and recover those
same identities from canonical wire values; generation is never recovery. Create
a fresh instance identity per process lifetime and a fresh command identity per new
logical command; retries retain the original command. Identity possession grants
no authority and resource IDs are never filesystem paths.

`Instant` retains seconds/nanoseconds without rounding. `ZonedInstant` preserves
the originating zone when semantically meaningful, refuses DST gaps and requires
an explicit offset for overlaps. Presentation converts a stored instant without
altering it. Durations use `IClock` monotonic timestamps from one clock instance,
never subtraction of wall-clock instants. `Clock` accepts a `TimeProvider` for
deterministic offline testing.

`EnumProjection<T>` preserves unknown response enum values but refuses to admit
them as known mutation values. Contracts' codecs retain unknown protobuf fields;
an unknown/read projection does not authorize a mutation or retry.

The nested Tests project contains offline value, clock, DST and compiler-negative
checks. Publication and exact artifact evidence are recorded in the delivery ledger.
