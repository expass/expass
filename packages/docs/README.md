# 📚 ExPass Docs

This package contains the Docusaurus documentation site for ExPass.

## 🛠️ Local development

From the repository root, use Node.js 24 and run:

```bash
npm ci
npm run docs:start
```

To build and preview the production site:

```bash
npm run docs:build
npm run docs:serve
```

The output is written to `packages/docs/build/`. From `packages/docs`, the
equivalent commands are `npm run start`, `npm run build`, and `npm run serve`.

## 🌐 Deployment

The GitHub Pages workflow builds the site on pushes to `develop` and deploys the
artifact using GitHub Actions. The custom domain is `https://expass.js.org/`;
Docusaurus uses `baseUrl: '/'`.

Manual deployment is also available from the repository root:

```bash
npm run docs:build
npm run docs:deploy
```

Manual deployment requires GitHub credentials with push access to the `gh-pages`
branch; Docusaurus may also require `GIT_USER`. It is separate from the Actions
artifact deployment workflow.
