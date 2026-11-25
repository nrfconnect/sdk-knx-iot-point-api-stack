# The twelve dimensions of a finding

A review run does every dimension against every file of the scope. The examples
are entry points, never a closing list. A dimension that this project carries
nowhere gets an explicit line with the reason, never a silent skip.

**1 — Correctness against the specification.** A deviation from the spec. A
missing requirement, a wrongly read boundary, a silently widened or narrowed
contract. The behaviour at a limit, at an empty input, at a maximum value.

**2 — Input handling and trust boundaries.** Where does foreign data enter?
Validation before use, length and range, encoding, a non-canonical form, a
duplicate or an unknown field. Does the code work on an input before the check?

**3 — Error handling and failure behaviour.** An ignored return value, a
swallowed error, an error path that continues instead of an end. Does the system
fail closed or open? A crash out of foreign input. An information leak in an
error text, a log or a trace.

**4 — State, lifecycle and order.** A state transition that the code allows in
the wrong order. The state after a restart, a crash or a power loss: persisted,
lost, or continued inconsistently? Does a change of state stand *before* or
*after* its check? A resource release on every path, the error paths included.

**5 — Concurrency.** Shared state with no synchronisation, a race condition,
TOCTOU, a deadlock, reentrancy. An assumption on execution order that nothing
guarantees. In this stack: an interrupt, a second thread of the port layer, and
a callback out of the event loop.

**6 — Resources and limits.** A leak of memory, a handle or a connection. An
allocation size out of foreign input. Unbounded growth of a buffer, a cache or a
queue. A missing timeout, a retry loop with no upper limit. In this stack: the
static pools, the transaction list, the observe list and the block-wise buffers.

**7 — Arithmetic and conversion.** Overflow and underflow, division by zero,
loss of precision, a lossy cast, a sign error. Judge by the behaviour of the
**release build**, never by the debug behaviour. An `assert` disappears there.

**8 — Security.** Access control and authorisation at every boundary. Secrets:
origin, storage, lifetime, visibility in a log and in a debug output. Injection
paths of the technology. Cryptography, where it exists: primitive, parameter,
nonce uniqueness, a constant-time comparison, the source of randomness, and a
verification whose result the code reads. A hardcoded credential. A dependency
with a known advisory.

**9 — API design and misuse.** Does a caller use the interface wrong with no
sign of it? A dangerous default, an order dependency with no guard, unclear
ownership of data. This is no question of style: misuse is the cause whose
symptoms appear in the other dimensions.

**10 — Test coverage.** Which requirement carries no test? A missing negative
test, boundary test, error-path test or state-transition test? A test that
proves nothing — with no assertion, on a mock instead of on behaviour, or so
fitted to the code that it freezes the defect? Does the code use every test
vector of the specification?

**11 — Unsafe constructs and dependencies.** A language-specific exit out of the
safety guarantees: name the invariant and do a check of it. In C: a pointer
arithmetic, a cast between two types of a different size, a variadic function, a
string function with no length. A dependency: version, maintenance state, known
advisories. An own implementation where a reviewed library exists. A feature
flag or a debug flag that switches a check off.

**12 — Maintainability, where it causes a defect.** Only where it leads to a
defect or hides one: dead code, duplicated logic that drifts apart, a comment
against the code, an orphan TODO at a security-relevant place. No style review,
no note on formatting.
