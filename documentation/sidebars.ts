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
    'agents',
    'mcp',
    'doctor',
    'python-api',
    'vulnerability-database',
    'server-usage',
    'reachability-analysis',
    'supported-languages',
    {
      type: 'category',
      collapsible: true,
      label: 'Reachability Concepts',
      items: [
        'concepts/reachability-model',
        'concepts/prioritization',
        'concepts/sbom-and-evidence'
      ]
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Language Guides',
      items: [
        'languages/rust-reachability',
        'languages/go-reachability',
        'languages/dotnet-reachability',
        'languages/jvm-js-python-php-reachability'
      ]
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Analyzers',
      items: [
        'analyzers/framework-reachability',
        'analyzers/semantic-reachability'
      ]
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Reports and Compliance',
      items: [
        'output/scan-directory',
        'output/vdr-guide',
        'output/vex-csaf-guide',
        'output/validate-command'
      ]
    },
    'env-var',
    'adv-usage',
    'migrate-v6-to-v7',
    'migrate-v5-to-v6',
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
    {
      type: 'category',
      collapsible: true,
      label: 'Tutorials',
      items: [
        'Lessons/java-semantic-analysis',
        'Lessons/dotnet-framework-analysis'
      ]
    },
  ],
};

export default sidebars;
