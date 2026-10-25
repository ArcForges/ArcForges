// SPDX-License-Identifier: AGPL-3.0-only

// Tests run in parallel, test by test (16-testing-strategy section 4): every test has its own in-process node (data root, endpoint, Linux
// slice), and the fixture ends only its own node's attempts and holders (named by their attempt on the command line). The node sees only
// itself and its attempts on the machine (InProcessNode.LiveMachine), so the other tests' load moves neither its budgets nor its pressure.
// A test that is timing-, CPU-share- or memory-sensitive, or that changes machine-wide state no per-test isolation can remove, carries
// [Trait("isolation", "exclusive")] and DisableParallelization = true: xUnit keeps it away from the parallel tests, and the scripts run the
// exclusive suite after every other suite with xUnit's parallelization off (--parallel none), one test at a time, because
// DisableParallelization does not keep it away from the DisableParallelization tests of other test classes (observed with xunit.v3
// 4.0.1; eng/test-suites.conf).
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.All)]

// A fixture reports what its test left running; this fails the test after it ran, next to the test's own failure.
[assembly: ArcForges.Tests.FailOnLeftovers]
