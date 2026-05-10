# Contributing to hash-it

Thank you for your interest in contributing to hash-it!

---

## Development Rules

All contributions must follow the [Project Rules](README.md):

- **TypeScript strict mode** — no `any` without justification
- **Zero custom cryptography** — use Node.js `crypto`, never roll your own
- **No hardcoded secrets** — environment variables only
- **95%+ test coverage** — all new security features require unit + integration tests
- **Conventional Commits** — `feat:`, `fix:`, `security:`, `docs:`, `test:`

---

## Getting Started

```bash
git clone https://github.com/notifycode/hash-it
cd hash-it
npm install
npm test
```

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests first (TDD preferred)
4. Ensure all CI checks pass:
   ```bash
   npm run lint
   npm test
   npm run build
   npm audit
   ```
5. Minimum **2 PR approvals** required
6. Security PRs require review from a cryptography expert

---

## Security PRs

Security improvements follow a stricter process:

1. Open a draft PR marked `[SECURITY]`
2. Request review from a maintainer with crypto expertise
3. Do NOT merge until all cryptographic assumptions are verified
4. Add a `security:` entry to `CHANGELOG.md`

---

## Commit Format

```
type(scope): short description

feat(token): add PS256 RSA-PSS support
fix(password): correct needsRehash comparison logic
security(encrypt): migrate CBC to Encrypt-then-MAC
docs(readme): add key rotation examples
test(session): add refresh token rotation tests
```

---

## Questions?

Open a GitHub Discussion or email dev@notifycode.org.
