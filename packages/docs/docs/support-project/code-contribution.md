---
title: "🛠️ Code contribution"
---

Help improve ExPass through pull requests, bug reports, documentation, and code
reviews. Contributions of any size are welcome.

## 🐛 Report a bug

[Open an issue](https://github.com/expass/expass/issues/new) with:

- What you expected and what actually happened.
- The ExPass package and version, Node.js version, and operating system.
- A minimal reproduction, including the relevant options and error message.

Use example passwords and secrets in reproductions. Search existing issues first
so related reports can stay together.

## 💡 Suggest an improvement

Use an issue to describe the problem you want to solve and your proposed approach.
For larger changes, discussing the design before implementation helps establish
the scope and identify effects on the public API or stored password format.

Documentation fixes, clearer examples, and improvements to error messages are
also useful contributions.

## 🔀 Submit a pull request

1. Fork [expass/expass](https://github.com/expass/expass) and create a branch from
   `develop`.
2. Make the change and add or update tests where behavior changes.
3. Update the documentation and examples when changing the public API.
4. Run the checks below and open a pull request targeting `develop`.

From the repository root, using Node.js 24:

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The build includes both library packages and the documentation site. For a
documentation change, you can also preview the site with `npm run docs:start`.

In the pull request, explain the problem, the resulting behavior, and how you
verified the change. Link any related issue and call out changes to configuration,
public method names, or encoded password compatibility.

## 👀 Review and improve

You can also help by reproducing reported bugs, reviewing open pull requests,
checking examples, or clarifying existing documentation.

For benchmarks, papers, and applications using ExPass, see
[Community & research](./community-and-research.md).
