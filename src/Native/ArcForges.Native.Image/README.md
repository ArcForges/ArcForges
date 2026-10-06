# ArcForges.Native.Image

Owned ABI 1.1 bindings for PNG, TIFF and EXR metadata and bounded region reads through
OpenImageIO/OpenEXR/Imath. Existing version/build/error exports remain compatible.
`ImageReader.Open` and `OpenAsync` take immutable brokered callback input, typed limits,
subimage/mip and a closed output format. `ReadRegion`/`ReadRegionAsync` return packed
unassociated RGBA8 in the reported source transfer, or linear premultiplied RGBA32F,
with an explicit row stride. Associated nonlinear input is unassociated before its
transfer conversion and premultiplied once for float output. Source channel names,
types and bit depths remain in immutable metadata; output conversion loss is explicit.

Instantiate readers only inside the approved restricted ContentSandbox helper. This
binding is not OS isolation. It owns the generation token and callback roots in a
SafeHandle; close drains borrowed operations before releasing input roots. Cancellation
is polled at callback/decode boundaries. Codec hangs or native crashes require the
helper supervisor's OS termination and invocation cleanup.

Input callbacks must return without waiting on another operation on that reader.
Reentrant reads report Busy; queued reads or closes from a callback are refused.
A synchronous callback close is deferred until the current borrowed read drains.
Repeated and backwards regions retain the same immutable brokered input, including
when an upstream PNG reader internally reopens to rewind.

Pin this package and its explicitly admitted Runtime.<rid> sibling at the same exact
published version. The retained loader requires win-x64 with an app-local hash manifest;
it never searches PATH or the current directory. Other RID production and package-only
acceptance remain NAT.22/NAT.30 responsibilities. Source does not prove new RID support.

The adapter uses the existing authored image open/info/tile/buffer-seal/ack/finish
protocol. No native pointer or opaque process token becomes a wire ID. Parent admission,
slot geometry, digest/coverage verification and final output acceptance remain the
ContentSandbox broker's responsibility.
