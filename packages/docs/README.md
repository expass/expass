# Expass Docs

This package contains the Docusaurus static site for Expass.

## Scripts

- `npm run start` — local dev server with hot reload
- `npm run build` — build static HTML into `build/`
- `npm run serve` — serve the production build locally
- `npm run deploy` — deploy to GitHub Pages (requires `GIT_USER`)

## Deployment

The config is set for GitHub Pages at `https://expass.github.io/expass/`.

To deploy:

```bash
# from repo root (after installing deps)
npm run docs:build
npm run docs:deploy
```

Or from within this package:

```bash
npm --workspace @expass/docs run build
npm --workspace @expass/docs run deploy
```

You may need to set `GIT_USER` and have push access to the `gh-pages` branch.

