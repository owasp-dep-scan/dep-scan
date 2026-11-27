import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// The site is organized around what a reader is trying to do: start, the
// results of a scan, what to scan, how to run it in CI and with agents, the
// reference pages, the upgrade guides, the contributor pages and the
// tutorials. Page order within a category follows the reading order, so the
// sidebar can be read as a short book on the tool.

const sidebars: SidebarsConfig = {
  documentationSidebar: [
    {
      type: 'category',
      collapsible: false,
      label: 'Start',
      items: [
        'start/overview',
        'start/installation',
        'start/first-scan',
        'start/vulnerability-database',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Understand the results',
      items: [
        'results/finding-model',
        'results/reachability',
        'results/exploitability',
        'results/evidence',
        'results/coverage',
        'results/prioritization',
        'results/triage-and-gating',
        'results/scan-directory',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Scan your software',
      items: [
        'targets/source-repositories',
        'targets/java-javascript-python-php',
        'targets/rust',
        'targets/go',
        'targets/dotnet',
        'targets/container-images',
        'targets/binaries',
        'targets/mobile-apps',
        'targets/memory-safety',
        'targets/supply-chain',
        'targets/licences',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Run it in CI and with agents',
      items: [
        'integrate/ci',
        'integrate/agents',
        'integrate/mcp',
        'integrate/agent-plugin',
        'integrate/agent-skills-toolchain',
        'integrate/python-api',
        'integrate/server',
        'integrate/vdr',
        'integrate/vex-csaf',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Reference',
      items: [
        'reference/cli',
        'reference/configuration',
        'reference/schemas',
        'reference/doctor',
        'reference/validate',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Upgrade',
      items: [
        'upgrade/migrate-v6-to-v7',
        'upgrade/migrate-v5-to-v6',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Develop',
      items: [
        'Develop/contributing',
        'Develop/development-setup',
        'Develop/debugging',
      ],
    },
    {
      type: 'category',
      collapsible: true,
      label: 'Tutorials',
      items: [
        'lessons/01-node-source-reachability',
        'lessons/02-go-service-golem',
        'lessons/03-container-image',
        'lessons/04-binaries-blint',
        'lessons/05-memory-safety-c',
        'lessons/06-supply-chain-licence',
        'lessons/07-ci-gating',
        'lessons/08-agent-workflow',
        'lessons/09-vulnerable-repos',
      ],
    },
  ],
};

export default sidebars;
