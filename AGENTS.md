# Repository instructions

- The public API stays neutral across operating systems. Platform detail stays inside its backend.
- An application's `ServiceName` addresses every secret it has already stored. Never change the value an application passes, and never give the library a default.
- Never log or commit a secret value, and never write one into a test assertion message.

## Operating-system boundaries

All OS-specific code in every Darkspyre project must live behind an OS-agnostic capability contract.

Portable consumers call that contract. Platform implementations own OS detection, native bindings and ABI layouts, native-library names and loading, system commands, platform paths, filesystem semantics, and platform-specific process and UI behaviour. Only platform composition selects the implementation. SDK contracts, plugins, extensions, core modules, and portable host code must not require consumers to know the operating system or call a platform implementation directly.

An interface that exposes OS-specific commands, types, paths, or layouts does not satisfy this rule. Reuse the existing capability seam. A platform without an implementation reports the capability unavailable through the same contract.

This boundary lets another operating system supply an implementation without changing portable consumers.

**Check.** Audit source and package configuration for OS branches, native imports, platform paths and commands, filesystem assumptions, and platform-only dependencies. Trace each hit through its callers and registration. Every OS-specific operation must remain inside a platform implementation selected through an OS-agnostic contract. A filename, namespace, annotation, or `IsMacOS()` guard alone does not establish that boundary.
