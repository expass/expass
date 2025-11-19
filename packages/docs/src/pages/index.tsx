import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import styles from './index.module.css';

export default function Home(): JSX.Element {
  return (
    <Layout
      title="Expass"
      description="Password encoder with salt + pepper and anti-parallelization">
      <header className={styles.heroBanner}>
        <div className={styles.container}>
          <img
            src="img/fingerprint-white.png"
           />
          <h1 className={styles.title}>Expass</h1>
          <p className={styles.subtitle}>Strong password encoding primitives for Node.js</p>
          <div className={styles.buttons}>
            <Link className="button button--primary" to="/docs/intro">
              Read the docs
            </Link>
            <Link className="button button--secondary" to="https://github.com/expass/expass">
              View on GitHub
            </Link>
          </div>
        </div>
      </header>
    </Layout>
  );
}

