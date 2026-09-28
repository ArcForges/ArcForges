# NAT.03 — sustained acquisition over a real transport

This isolated early-risk probe exercises a scalar acquisition stream over an actual operating-system TCP loopback connection. NAT.03 specifies a bounded single-channel acceptance floor of 1,000,000 scalar samples/second for at least 10 seconds over real localhost TCP. This is a probe-only measurement, not a shipping SLA, marketing claim, or downstream performance target.

Each 24-byte wire frame contains a 64-bit sequence, a 64-bit source timestamp, and a 64-bit scalar value. The TCP reader publishes frames to a fixed-capacity single-producer/single-consumer ring. The capture sink drains independently of the view. The live view copies a bounded history and min/max downsamples it to a fixed display budget; pause disables only view rendering.

The acceptance command restores/builds/runs the self-contained project without adding test or transport packages:

```powershell
dotnet restore benchmarks/probes/acquisition/AcquisitionProbe.csproj --locked-mode
dotnet build benchmarks/probes/acquisition/AcquisitionProbe.csproj -c Release --no-restore
dotnet run --project benchmarks/probes/acquisition/AcquisitionProbe.csproj -c Release --no-build -- --self-test --evidence benchmarks/probes/acquisition/evidence/nat-03-run.json
```

The run sends 14.4 million samples at a nominal 1.2 million samples/second (a 12-second traffic window) to leave scheduling margin for the >=10-second measured acceptance floor. It reports observed samples/second, fixed ring and wire-buffer sizes, peak process working set and managed heap, committed/dropped counts, and a capture checksum. Separate real-TCP cases force a full ring and premature peer close. Both must retain timestamped gap evidence. A pause case verifies capture continues while the view is paused, and the downsampler fixture verifies a narrow spike survives the point budget.

The fixed ring is a bounded transient queue, not the product's durable recording store. The probe's capture sink counts and checksums records to prove the queue can be drained without back-pressure; durability, hardware driver behavior, and product display integration remain outside NAT.03.
