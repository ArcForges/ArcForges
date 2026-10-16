// SPDX-License-Identifier: AGPL-3.0-only

// Tests run in parallel, test by test (16-testing-strategy section 4): every test has its own platform (node name, root job and data root)
// and tracks only the processes of its own jobs.
// A test that is timing-, CPU-share- or memory-sensitive, or that changes machine-wide state no per-test isolation can remove, carries
// [Trait("isolation", "exclusive")] and DisableParallelization = true: xUnit runs it alone after the others, and the scripts run the
// exclusive suite after every other suite (eng/test-suites.conf).
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.All)]
