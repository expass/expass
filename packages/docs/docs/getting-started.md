---
title: Getting Started
---

This guide walks you through installing and using Expass.

## Install

Install the packages you need in your project:

```bash
npm install @expass/node
```

## Quick usage

```ts
import { NodeExpass } from '@expass/node';

const PASSWORD_SECRET = process.env['PASSWORD_SECRET'];

// Create Expass instance
const expass = new Expass(PASSWORD_SECRET);

// Encode a password with default config
const encoded = await expass.encode('s3cret');

// Verify later
const isValid = await expass.verify('s3cret', encoded);
```
