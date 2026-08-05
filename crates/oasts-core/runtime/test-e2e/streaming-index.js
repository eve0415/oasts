// The streaming suite runs in its own process, deliberately.
//
// `msw.test.ts` calls `setupServer(...).listen()` in a top-level `before`, and node:test runs every
// top-level hook before any test — so once that suite is in the process, MSW's interceptor sits in
// front of every request for the whole run, this suite's included. Reading a response to the end
// still works through it, but cancelling a stream part-way does not: the cancel never reaches the
// socket and the read never settles, which hangs the run rather than failing it. Measuring what a
// real socket does is the entire point of this suite, so it gets a process with nothing intercepting.
import "./streaming.test.ts";
