# Repository instructions

- `SecureStore` is the single canonical implementation of operating system credential storage. Development consumers use sibling project references; release consumers reference the private NuGet package; do not copy its source into an application repository.
- The public API stays neutral across operating systems. Platform detail stays inside its backend.
- An application's `ServiceName` addresses every secret it has already stored. Never change the value an application passes, and never give the library a default.
- Never log or commit a secret value, and never write one into a test assertion message.
- Keep the solution at zero warnings and run restore, build, test, format verification, pack, and the dependency vulnerability audit before release.
- Package releases use semantic versions and immutable Git tags. Never overwrite an already-published package version.

## Local development and releases

`Darkspyre.ML.Tokenizers` is the explicit NuGet exception. It remains a package in source mode; changes to that stable fork are consumed through a NuGet version update.

Normal builds and tests use local source from the seven sibling workspace worktrees: agent-ds,
AgentDSPlugins, Inference, TensorSharp, RightSize, SecureStore and PersistenceStore. No source-root
flags or per-session local props files are required. Missing source must fail without a package fallback.
Do not build in primary checkouts or create interim NuGet packages. Read `~/.agent-ds/build-instructions.md`.

`DarkspyreDependencyMode=Packages` is explicit release publishing/deployment mode. Debug/Release,
signing and interim installation do not select it. Test copies retain compatible prebuilt GGML driver
hardlinks. Signed bundles may copy prebuilt drivers before signing. Native compilation always needs
an explicit request.
