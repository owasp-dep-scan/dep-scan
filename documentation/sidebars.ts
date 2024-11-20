import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  documentationSidebar: [
    'dep-scan',
    'getting-started',
    'cli-usage',
    'server-usage',
    'reachability-analysis',
    'supported-languages',
    'env-var',
    'adv-usage',
    {
      type: 'category',
      collapsible: true,
      label: 'Develop',
      // link: {
      //   type: 'doc',
      //   id: 'Develop/develop'
      // },
      items: [
        'Develop/contributing',
        'Develop/getting-started-development',
        'Develop/debugging',
        // 'Develop/core-concepts',
        // 'Develop/testing-quality',
        // 'Develop/help'
      ]
    },
  ],
};

export default sidebars;
