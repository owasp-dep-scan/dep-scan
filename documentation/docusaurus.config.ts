import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';


const config: Config = {
  title: 'OWASP dep-scan',
  tagline: 'Next generation security audit',
  favicon: 'img/dep-scan-large.png',

  url: 'https://depscan.readthedocs.io/',
  baseUrl: '/',

  organizationName: 'owasp-dep-scan', // Usually your GitHub org/user name.
  projectName: 'dep-scan', // Usually your repo name.

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',

          routeBasePath: '/',

          editUrl:
            'https://github.com/owasp-dep-scan/dep-scan/tree/master/documentation',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },

          editUrl:
            'https://github.com/owasp-dep-scan/dep-scan/tree/master/documentation',
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'OWASP dep-scan',
      logo: {
        alt: 'dep-scan Logo',
        src: 'img/dep-scan-large.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'documentationSidebar',
          position: 'left',
          label: 'Docs',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Community',
          items: [
            {
              label: 'Github',
              href: 'https://github.com/owasp-dep-scan/dep-scan',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} OWASP Foundation.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
