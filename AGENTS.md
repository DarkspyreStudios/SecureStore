# Repository instructions

- `SecureStore` is the single canonical implementation of operating system credential storage. Consumers reference the private NuGet package; do not copy its source into an application repository.
- The public API stays neutral across operating systems. Platform detail stays inside its backend.
- An application's `ServiceName` addresses every secret it has already stored. Never change the value an application passes, and never give the library a default.
- Never log or commit a secret value, and never write one into a test assertion message.
- Keep the solution at zero warnings and run restore, build, test, format verification, pack, and the dependency vulnerability audit before release.
- Package releases use semantic versions and immutable Git tags. Never overwrite an already-published package version.
