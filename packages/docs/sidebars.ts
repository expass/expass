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
    {
      type: 'category',
      label: '🤝 Support project',
      items: [
        'support-project/code-contribution',
        'support-project/community-and-research',
        'support-project/donate',
      ],
      collapsed: false,
    },
  ],
};

export default sidebars;

