# Repository instructions

- The public API stays neutral across operating systems. Platform detail stays inside its backend.
- An application's `ServiceName` addresses every secret it has already stored. Never change the value an application passes, and never give the library a default.
- Never log or commit a secret value, and never write one into a test assertion message.
