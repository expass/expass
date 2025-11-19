import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'intro',
    {
      type: 'category',
      label: 'Guides',
      items: [
          'getting-started',
          'customization',
          'validation',
      ],
      collapsed: false,
    },
  ],
};

export default sidebars;

