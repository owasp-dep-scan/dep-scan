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

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',

  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],
  plugins: [
    [
      '@docusaurus/plugin-client-redirects',
      {
        // Every id the pre-2026 site published or the dep-scan code prints
        // keeps answering: moved pages redirect to their new location, and
        // merged pages redirect to the page that carries their content.
        redirects: [
          {from: '/getting-started', to: '/'},
          {from: '/vulnerability-database', to: '/start/vulnerability-database'},
          {from: '/concepts/reachability-model', to: '/results/reachability'},
          {from: '/concepts/exploitability', to: '/results/exploitability'},
          {from: '/concepts/sbom-and-evidence', to: '/results/evidence'},
          {from: '/concepts/prioritization', to: '/results/prioritization'},
          {from: '/output/scan-directory', to: '/results/scan-directory'},
          {from: '/supported-languages', to: '/targets/source-repositories'},
          {from: '/reachability-analysis', to: '/targets/source-repositories'},
          {from: '/analyzers/framework-reachability', to: '/targets/source-repositories'},
          {from: '/analyzers/semantic-reachability', to: '/targets/source-repositories'},
          {from: '/languages/jvm-js-python-php-reachability', to: '/targets/java-javascript-python-php'},
          {from: '/languages/rust-reachability', to: '/targets/rust'},
          {from: '/languages/go-reachability', to: '/targets/go'},
          {from: '/languages/dotnet-reachability', to: '/targets/dotnet'},
          {from: '/agents', to: '/integrate/agents'},
          {from: '/output/vdr-guide', to: '/integrate/vdr'},
          {from: '/output/vex-csaf-guide', to: '/integrate/vex-csaf'},
          {from: '/mcp', to: '/integrate/mcp'},
          {from: '/agent-plugin', to: '/integrate/agent-plugin'},
          {from: '/agent-skills-toolchain', to: '/integrate/agent-skills-toolchain'},
          {from: '/python-api', to: '/integrate/python-api'},
          {from: '/server-usage', to: '/integrate/server'},
          {from: '/cli-usage', to: '/reference/cli'},
          {from: '/env-var', to: '/reference/configuration'},
          {from: '/doctor', to: '/reference/doctor'},
          {from: '/output/validate-command', to: '/reference/validate'},
          {from: '/migrate-v6-to-v7', to: '/upgrade/migrate-v6-to-v7'},
          {from: '/migrate-v5-to-v6', to: '/upgrade/migrate-v5-to-v6'},
          // The three old /Develop/<page> ids are the new pages' own ids in
          // lowercase, and a redirect from one to the other collides with
          // the built page on a case-insensitive filesystem, so the build
          // machine cannot create those three files. The old URLs answer
          // the new pages through the server's own case-insensitive
          // fallback where it has one; noted in the page map.
          {from: '/Lessons/java-semantic-analysis', to: '/lessons/01-node-source-reachability'},
          {from: '/Lessons/dotnet-framework-analysis', to: '/lessons/02-go-service-golem'},
          {from: '/adv-usage', to: '/reference/cli'},
        ],
      },
    ],
  ],

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

          // Keep the file names as the ids, numeric prefixes included, so a
          // lesson's id is what its directory and script are named.
          numberPrefixParser: false,

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
