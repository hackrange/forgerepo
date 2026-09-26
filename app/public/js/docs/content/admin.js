// ForgeRepo portal: the administrator guide.
// Author: Tim Rice
//
// how the system decides, and how to run every part of it. every claim here was read from the code and checked on
// the documentation box, see Documentation_Instructions.md before changing one

import { register } from '../diagrams.js';

register('admin-pipeline', {
  w: 760, h: 330, title: 'The checks every install goes through, in order',
  nodes: [
    { id: 'ask', x: 10, y: 20, w: 130, h: 56, text: 'npm, pip or docker asks', kind: 'client' },
    { id: 'kill', x: 185, y: 20, w: 130, h: 56, text: '1. Kill switch', kind: 'decision' },
    { id: 'rules', x: 360, y: 20, w: 130, h: 56, text: '2. Rules for this token', kind: 'decision' },
    { id: 'squat', x: 535, y: 20, w: 215, h: 56, text: '3. Lookalike name check', kind: 'decision' },
    { id: 'fetch', x: 535, y: 130, w: 215, h: 64, text: '4. Fetch or use the cache (reserved names, registry mode)', kind: 'registry' },
    { id: 'trim', x: 250, y: 130, w: 240, h: 64, text: '5. Quarantine, vulnerabilities, cooling off, licenses', kind: 'decision' },
    { id: 'scan', x: 10, y: 130, w: 195, h: 64, text: '6. File hash kill and scan before serve', kind: 'decision' },
    { id: 'no', x: 185, y: 255, w: 200, h: 56, text: '403 with the reason, maybe a request', kind: 'bad' },
    { id: 'ok', x: 10, y: 255, w: 130, h: 56, text: 'Served', kind: 'good' }
  ],
  edges: [
    { from: 'ask', to: 'kill' }, { from: 'kill', to: 'rules' }, { from: 'rules', to: 'squat' }, { from: 'squat', to: 'fetch' },
    { from: 'fetch', to: 'trim' }, { from: 'trim', to: 'scan' }, { from: 'scan', to: 'ok', kind: 'good' },
    { from: 'trim', to: 'no', label: 'any check says no', kind: 'bad' }
  ]
});

register('admin-rule-order', {
  w: 760, h: 160, title: 'How the winning rule is picked',
  nodes: [
    { id: 'p', x: 10, y: 20, w: 130, h: 60, text: 'Higher priority', kind: 'decision' },
    { id: 's', x: 165, y: 20, w: 130, h: 60, text: 'Narrower scope (app, env)', kind: 'decision' },
    { id: 'e', x: 320, y: 20, w: 130, h: 60, text: 'Exact name, then longer pattern', kind: 'decision' },
    { id: 'd', x: 475, y: 20, w: 130, h: 60, text: 'Deny before allow', kind: 'decision' },
    { id: 'm', x: 630, y: 20, w: 120, h: 60, text: 'Winner decides', kind: 'good' },
    { id: 'none', x: 475, y: 105, w: 275, h: 46, text: 'No rule matches: whitelist blocks, blacklist allows', kind: 'outside' }
  ],
  edges: [{ from: 'p', to: 's', label: 'tie' }, { from: 's', to: 'e', label: 'tie' }, { from: 'e', to: 'd', label: 'tie' }, { from: 'd', to: 'm' }]
});

register('admin-modes', {
  w: 760, h: 170, title: 'Registry modes',
  nodes: [
    { id: 'n', x: 10, y: 30, w: 220, h: 110, text: 'Normal\nFetches anything the rules allow', kind: 'good' },
    { id: 'd', x: 270, y: 30, w: 220, h: 110, text: 'Degraded\nNo brand new names are fetched. Names already held still refresh', kind: 'decision' },
    { id: 'l', x: 530, y: 30, w: 220, h: 110, text: 'Lockdown\nNothing is fetched. Only files on disk are offered. Quarantine acts strict', kind: 'bad' }
  ],
  edges: [{ from: 'n', to: 'd', label: 'raise' }, { from: 'd', to: 'l', label: 'raise' }]
});

register('admin-confusion', {
  w: 760, h: 220, title: 'Reserved names stop dependency confusion',
  nodes: [
    { id: 'dev', x: 10, y: 80, w: 140, h: 60, text: 'npm install @acme/widgets', kind: 'client' },
    { id: 'us', x: 200, y: 80, w: 150, h: 60, text: '{{name}}', kind: 'registry' },
    { id: 'res', x: 400, y: 80, w: 150, h: 60, text: 'Is @acme/* reserved?', kind: 'decision' },
    { id: 'local', x: 600, y: 10, w: 150, h: 60, text: 'Serve the copy published here', kind: 'good' },
    { id: 'pub', x: 600, y: 150, w: 150, h: 60, text: 'Public npm is never asked', kind: 'bad' }
  ],
  edges: [{ from: 'dev', to: 'us' }, { from: 'us', to: 'res' }, { from: 'res', to: 'local', label: 'yes', kind: 'good' }, { from: 'res', to: 'pub', label: 'yes', kind: 'bad' }]
});

register('admin-incident', {
  w: 760, h: 180, title: 'Responding to a malicious release',
  nodes: [
    { id: 'k', x: 10, y: 55, w: 160, h: 70, text: '1. Kill it, with a reason', kind: 'bad' },
    { id: 'w', x: 205, y: 55, w: 160, h: 70, text: '2. Who pulled it (last 30 days)', kind: 'decision' },
    { id: 'c', x: 400, y: 55, w: 160, h: 70, text: '3. Consumers: apps and pipelines', kind: 'decision' },
    { id: 'f', x: 595, y: 55, w: 155, h: 70, text: '4. Fix, then lift the kill', kind: 'good' }
  ],
  edges: [{ from: 'k', to: 'w' }, { from: 'w', to: 'c' }, { from: 'c', to: 'f' }]
});

var ADMIN = {
  id: 'admin',
  title: 'Administrator Guide',
  needs: ['settings:write'],
  intro: 'How {{name}} decides what gets through, how to set it up, and how to run every part of it day to day and during an incident.',
  groups: [
    // ================================================================================================ how it works
    {
      id: 'how', label: 'How it works',
      topics: [
        {
          id: 'admin-overview', title: 'How {{name}} works',
          summary: 'One registry for npm, PyPI and container images that checks every download against your rules and your security settings.',
          keywords: ['architecture', 'overview', 'how it works', 'proxy', 'cache', 'pipeline', 'order of checks'],
          blocks: [
            { t: 'p', text: '{{name}} answers npm, pip and docker at **{{host}}**. It fetches packages and images from the public registries, keeps a copy, and serves them only when every check agrees. Nothing is installed straight from the internet.' },
            { t: 'diagram', id: 'admin-pipeline', caption: 'The order of checks for a download. Metadata requests go through the same checks and simply leave out versions that would fail.' },
            { t: 'steps', items: [
              '**Kill switch.** Beats everything, including allow rules and audit mode.',
              '**Rules.** Whitelist or blacklist, scoped by the token\'s application and environment.',
              '**Lookalike names.** Warns or blocks names that imitate popular packages.',
              '**Fetch.** Reserved names are never fetched from outside. Degraded and lockdown modes limit what is fetched.',
              '**Holds and policies.** Quarantine holds, safe version resolution for known vulnerabilities, cooling off for brand new releases, and license rules.',
              '**Last checks on the file.** A kill by file hash, and an optional malware or image scan before the file is served.'
            ] },
            { t: 'h', text: 'Two ways a version is left out' },
            { t: 'list', items: [
              '**In metadata.** When npm or pip asks which versions exist, blocked versions are removed and `latest` moves to the newest allowed version. The client picks an allowed version on its own.',
              '**On download.** A lock file asks for an exact file. That request runs every check again and gets a 403 with the reason.'
            ] },
            { t: 'note', text: 'Checks run on the server for every request. Hiding a button in the portal is only tidiness. Roles are enforced by the API.' },
            { t: 'see', ids: ['admin-rules-order', 'admin-scope', 'admin-modes'] }
          ]
        },
        {
          id: 'admin-scope', title: 'Applications, environments and token scope',
          summary: 'Tokens carry an application and environment, and rules and waivers can apply to just those.',
          keywords: ['scope', 'application', 'environment', 'production', 'token scope', 'per team rules', 'lifecycle'],
          blocks: [
            { t: 'p', text: 'Every token can belong to one application and one environment, like **storefront** in **production**. {{name}} reads the scope only from the token, never from anything the client sends, so it cannot be faked.' },
            { t: 'list', items: [
              'A rule with an application or environment only applies to tokens in that scope. A rule with neither applies to everyone.',
              'At the same priority, a scoped rule beats a rule for everyone.',
              'A request with no token only gets rules that apply to everyone.',
              'Waivers can be scoped the same way, except license waivers, which always apply to everyone.',
              'The traffic log, Consumers and the SBOM export group downloads by application and environment.'
            ] },
            { t: 'steps', items: [
              'Open **Settings**, then the **Applications** tab, and add the applications and environments you use. Tick **Production** on production environments.',
              'On **Tokens**, set the application and environment of each pipeline token. Only admins can change these.',
              'Write scoped rules on **Rules** with **Only for application** and **Only in environment**.'
            ] },
            { t: 'tip', text: 'Use one token per application per environment. A token shared by two applications can only name one of them, and the traffic log will blame the wrong team.' },
            { t: 'h', text: 'Lifecycle stages' },
            { t: 'p', text: 'With **Enforce lifecycle stages** on (Settings, Policy), a production environment only gets versions promoted to the production stage on the **Artifacts** page, and a version at the blocked stage is refused to everyone. Lifecycle can only take away an allow, never add one.' }
          ]
        }
      ]
    },
    // ================================================================================================ first setup
    {
      id: 'setup', label: 'First setup',
      topics: [
        {
          id: 'admin-first-setup', title: 'First setup checklist',
          summary: 'The settings to review before developers start using {{name}}.',
          keywords: ['setup', 'install', 'getting started', 'checklist', 'public url', 'configure', 'onboarding'],
          blocks: [
            { t: 'steps', items: [
              '**Change the admin password** on **Your account**, and keep a second local admin so single sign-on problems cannot lock you out.',
              '**Public address.** Settings, **Cache** tab, **Public url**: set it to **{{origin}}**. Error messages and these docs use it.',
              '**Name and branding.** Settings, **Policy** tab: **Name shown in the portal**, a header icon and a favicon.',
              '**Package types.** Settings, **Registries** tab: switch on PyPI and container images if you need them.',
              '**Upstream registries.** Add Docker Hub as `https://registry-1.docker.io`, and any internal registries. See [Upstream registries](#docs/admin-registries).',
              '**Policy.** Pick whitelist or blacklist, and consider starting in audit mode. See [Whitelist, blacklist and audit mode](#docs/admin-policy-modes).',
              '**Tokens.** Turn on **Require tokens** once pipelines have tokens. See [Require tokens](#docs/admin-require-tokens).',
              '**Portal network.** Allow only your office and VPN networks to reach the portal. See [Portal allow list and break glass](#docs/admin-whitelists).',
              '**Email.** Settings, **Email** tab, so approvers hear about requests and admins hear about malware and kills.',
              '**Single sign-on**, if you use one. See [Single sign-on](#docs/admin-sso).'
            ] },
            { t: 'shot', id: 'admin-dashboard', caption: 'The dashboard is the best place to check that traffic is flowing after setup.' }
          ]
        },
        {
          id: 'admin-registries', title: 'Upstream registries and package types',
          summary: 'Where {{name}} fetches from, how names are routed, and the Docker Hub address.',
          keywords: ['upstream', 'registry', 'registries', 'docker hub', 'registry-1.docker.io', 'mirror', 'artifactory', 'nexus', 'pattern', 'fallback', 'pypi enabled', 'oci enabled'],
          blocks: [
            { t: 'p', text: 'Open **Settings**, then the **Registries** tab.' },
            { t: 'shot', id: 'admin-settings-registries' },
            { t: 'h', text: 'Package types' },
            { t: 'list', items: [
              'npm is always on.',
              '**PyPI registry** and **container images** are off until you switch them on.',
              '**Upstream registry enabled** is a big switch: off means nothing new is fetched, cached copies are still served, and everything else gets a 503.'
            ] },
            { t: 'h', text: 'Upstream registries' },
            { t: 'p', text: 'Each type has one default registry and any number of extra ones with a **Pattern**. Rows save as soon as you click **save**, separately from **Save settings**.' },
            { t: 'table', head: ['Field', 'What it does'], rows: [
              ['Address', 'The registry URL. For Docker Hub use `https://registry-1.docker.io`. A Docker Hub website address like hub.docker.com is corrected for you when you save.'],
              ['Pattern', 'Which names go to this registry, like `@acme/*`. The first match wins: an exact name beats a pattern, and a longer pattern beats a shorter one. A bare `*` is refused.'],
              ['Priority', '0 to 100000, default 100. Used when patterns tie.'],
              ['Token', 'Sent only to that registry. For images, write it as `username:access-token`. Stars mean keep the current token. Tokens are never exported.'],
              ['fall back', 'Off by default. When on, a name this registry does not have is asked of the default registry. Leave it off for internal scopes, or dependency confusion becomes possible.']
            ] },
            { t: 'warn', text: 'A disabled registry refuses its names with a 503. It never quietly sends them to another registry.' },
            { t: 'note', text: 'A cached copy remembers which registry it came from. If you move a name to a different registry, the old copy is not served and the name is fetched again. No purge is needed.' }
          ]
        },
        {
          id: 'admin-require-tokens', title: 'Require tokens',
          summary: 'Make every npm, pip and docker client prove who it is.',
          keywords: ['require auth', 'require tokens', 'anonymous', '401', 'authentication', 'npm clients only'],
          blocks: [
            { t: 'p', text: 'Out of the box anyone who can reach {{host}} can pull what the rules allow. Turning on tokens means every download is tied to a person or a pipeline, and rules can be scoped by application and environment.' },
            { t: 'steps', items: [
              'Give every pipeline a token first, placed in its application and environment.',
              'Open **Tokens**. Under **Who can pull packages**, tick **Require tokens** and confirm.',
              'Watch **Traffic** for 401 answers from clients you missed.'
            ] },
            { t: 'warn', text: 'Any client without a token stops working right away, including CI jobs.' },
            { t: 'p', text: 'Settings, Registries, **Only answer package managers** sends a 404 to browsers and scanners that are not npm clients.' }
          ]
        },
        {
          id: 'admin-branding-email', title: 'Name, branding and email',
          summary: 'Make the portal look like yours and let it send mail.',
          keywords: ['branding', 'logo', 'icon', 'favicon', 'registry name', 'email', 'smtp', 'microsoft 365', 'graph', 'digest', 'test email'],
          blocks: [
            { t: 'h', text: 'Name and branding' },
            { t: 'list', items: [
              'Settings, **Policy**, **Name shown in the portal**: the header, sign in page, browser tab, these docs and the PDF.',
              '**Header icon** and **Favicon** save as soon as you pick a file. PNG, JPEG, GIF or WebP (the favicon also takes ICO), 16 to 1024 pixels, 256 KB at most. SVG is refused. **Use the default** puts the anvil back.'
            ] },
            { t: 'h', text: 'Email' },
            { t: 'steps', items: [
              'Settings, **Email** tab, tick **Send email** and set the from address.',
              'Pick **smtp** (server, port, encryption, user) or **graph** for Microsoft 365 (tenant, client id, secret, sending mailbox).',
              'Use **Send a test** and check the mail log table below it.'
            ] },
            { t: 'table', head: ['Email', 'Who gets it', 'When'], rows: [
              ['Requests to decide', 'Anyone who can decide requests', 'Hourly digest'],
              ['Your requests were decided', 'The person who asked, and the token contact address', 'Hourly digest'],
              ['Integrity alerts', 'People who can resolve them', 'Hourly digest'],
              ['Waivers waiting or ending soon', 'People who can grant waivers', 'Daily'],
              ['Malware found', 'Admins', 'About a minute after a detection'],
              ['Kill switch used', 'Admins and approvers', 'Right away, with who pulled it'],
              ['Registry mode changed', 'Admins', 'Right away']
            ] }
          ]
        }
      ]
    },
    // ================================================================================================ people and access
    {
      id: 'people', label: 'People and access',
      topics: [
        {
          id: 'admin-users', title: 'Users and roles',
          summary: 'Add people, pick their role, unlock them, and act as them to see what they see.',
          keywords: ['users', 'roles', 'add user', 'viewer', 'developer', 'publisher', 'approver', 'admin', 'unlock', 'lockout', 'reset password', 'switch off', 'disable user'],
          blocks: [
            { t: 'shot', id: 'admin-users' },
            { t: 'table', head: ['Role', 'Adds'], rows: [
              ['viewer', 'Read rules, packages and vulnerabilities, review a file, and their own requests.'],
              ['developer', 'Tokens, requests, withdrawing their own requests, and dependency trees.'],
              ['publisher', 'Publishing npm and PyPI packages and pushing images under reserved names. Usually a CI account.'],
              ['approver', 'Rules, rule imports, all requests, request and waiver decisions, kills, and purging packages.'],
              ['admin', 'Settings, users, every token, traffic, the audit trail, cache purges and backups.']
            ] },
            { t: 'steps', items: [
              'Under **Add someone**, fill in the username, name, email, role and a starting password.',
              'Click **Create the account**. They must change the password the first time they sign in.'
            ] },
            { t: 'h', text: 'Row actions' },
            { t: 'list', items: [
              '**switch off** stops an account without deleting its history. Changing a role, switching off or resetting a password ends that person\'s sessions.',
              '**unlock** clears a lockout. Accounts lock after **Bad passwords before a lockout** (default 5) for **How long a lockout lasts** (default 15 minutes).',
              '**reset password** sets a new one they must change.',
              '**rename** keeps the role, tokens and history.',
              '**impersonate** lets you act as a non-admin for up to 30 minutes. A red bar with **Stop** stays on screen, and the audit trail records every action as "admin as them".'
            ] },
            { t: 'note', text: 'You cannot demote, switch off or delete the last admin, or remove your own admin role.' },
            { t: 'h', text: 'Passwords and sessions' },
            { t: 'p', text: 'Settings, **Access** tab: **Shortest allowed password** (default 12), lockout settings and **Portal idle timeout in minutes** (default 60). Passwords need three of lower case, upper case, numbers and symbols, and cannot contain the username or common words.' }
          ]
        },
        {
          id: 'admin-sso', title: 'Single sign-on',
          summary: 'Sign in with your OpenID Connect provider and map its groups to roles.',
          keywords: ['sso', 'single sign on', 'oidc', 'openid', 'okta', 'entra', 'azure ad', 'groups', 'role mapping', 'enable_local_login', 'locked out'],
          blocks: [
            { t: 'p', text: 'Settings, **SSO** tab. OpenID Connect is supported. SAML is not.' },
            { t: 'steps', items: [
              'In your provider, register an app with the redirect address `{{origin}}/_api/sso/callback`.',
              'Fill in **Provider address** (https), **Client id** and **Client secret**.',
              'Pick **Role a new account comes in as**: viewer, developer, publisher or approver. Admin is never given automatically.',
              'Optionally map groups in **Roles from the provider\'s groups**, one rule per line, like `approver = platform-team, security`.',
              'Click **Check the provider**, then **Save settings**, and sign in from a private window before you log out.'
            ] },
            { t: 'code', file: 'Roles from the provider\'s groups', text: '# strongest matching role wins\nadmin = repo-admins\napprover = platform-team, appsec\npublisher = release-bots\ndeveloper = engineering' },
            { t: 'list', items: [
              '**What is accepted**: `both` keeps password sign in, `sso_only` turns it off. A half configured `sso_only` still allows passwords, so you cannot lock yourself out by accident.',
              '**Keep roles in step on every sign in** updates roles from groups each time, but never demotes the last admin.',
              '**Refuse anybody no rule matches** turns group mapping into an access list.',
              'People are matched to existing accounts by email first, then by username.'
            ] },
            { t: 'h', text: 'Locked out by SSO' },
            { t: 'code', lang: 'bash', file: 'on the server', text: './enable_local_login.sh --status        # look, change nothing\n./enable_local_login.sh                 # allow password sign in again\n./enable_local_login.sh --off-sso       # also switch SSO off\n./enable_local_login.sh --admin admin   # clear a lockout on that account' },
            { t: 'note', text: 'The script cannot create accounts or set passwords. Keep one local admin with a strong password in your vault.' }
          ]
        },
        {
          id: 'admin-tokens', title: 'Managing every token',
          summary: 'See every token, who owns it, where it is used, and revoke any of them.',
          keywords: ['tokens', 'all tokens', 'revoke', 'owner', 'last used', 'expire', 'rotate', 'leaked token'],
          blocks: [
            { t: 'p', text: 'As an admin, **Tokens** lists every token with its **Owner**, application, environment, contact address, first characters, expiry and when and where it was last used.' },
            { t: 'list', items: [
              'Change a token\'s application or environment in place. It only affects traffic from then on.',
              '**revoke** stops a token at once. Tokens are revoked one at a time.',
              'Tokens can last up to 3650 days, or never expire with 0. Prefer short lived pipeline tokens.'
            ] },
            { t: 'warn', text: 'A leaked token: revoke it, then search **Traffic** for its name to see what it downloaded, and from which address.' }
          ]
        },
        {
          id: 'admin-whitelists', title: 'Portal allow list and break glass',
          summary: 'Hide the portal from networks you do not trust, with an emergency way back in.',
          keywords: ['ip allow list', 'whitelist', 'network', 'cidr', 'acl', 'break glass', 'emergency access', 'whitelist.sh', '404', 'registry clients', 'github actions ranges'],
          blocks: [
            { t: 'shot', id: 'admin-whitelists' },
            { t: 'h', text: 'Whitelist Admin Portal' },
            { t: 'steps', items: [
              'Under **Allow a network**, add your office and VPN ranges, or click **Add the address I am on**.',
              'Click **Switch the filter on**. It refuses unless your own address is on the list.'
            ] },
            { t: 'p', text: 'From any other address, `/_admin` and `/_api` answer a plain 404, so the portal does not even appear to exist.' },
            { t: 'h', text: 'Break glass keys' },
            { t: 'p', text: 'A break glass key lets someone in from an unlisted network in an emergency. Under **Make a key**, set how many times it can be used, how many minutes of access it grants and when the key expires. The person opens `{{portal}}/?bgt=<key>`. Keys are stored hashed, tries are throttled, and every use is audited. **Revoke every active grant** ends them all.' },
            { t: 'h', text: 'Whitelist Clients' },
            { t: 'list', items: [
              '**Only allow npm clients from the networks below** limits the registry itself, not just the portal.',
              '**Let a valid token through from any network** lets remote developers in with a token.',
              '**Allow GitHub SaaS** keeps GitHub Actions runner ranges up to date automatically.'
            ] },
            { t: 'code', lang: 'bash', file: 'on the server', text: './whitelist.sh 10.20.0.0/16 --admin --label "office"\n./whitelist.sh 203.0.113.7 --client --label "build server"' },
            { t: 'note', text: 'The script adds networks but does not switch a filter on. The running server notices within 5 seconds.' },
            { t: 'warn', text: 'Behind a reverse proxy, the proxy must set `X-Forwarded-For` to the real client address, and nothing but the proxy may reach the container port. Otherwise the allow list can be fooled.' }
          ]
        }
      ]
    },
    // ================================================================================================ rules and requests
    {
      id: 'rules', label: 'Rules and approvals',
      topics: [
        {
          id: 'admin-policy-modes', title: 'Whitelist, blacklist and audit mode',
          summary: 'Choose whether unknown packages are blocked or allowed, and how to switch safely.',
          keywords: ['whitelist', 'blacklist', 'allow list', 'deny list', 'policy mode', 'audit mode', 'learning mode', 'rollout', 'migrate'],
          blocks: [
            { t: 'shot', id: 'admin-settings-policy' },
            { t: 'table', head: ['Mode', 'No rule matches', 'Best for'], rows: [
              ['whitelist', 'Blocked', 'The strongest protection. Every package needs an allow rule.'],
              ['blacklist', 'Allowed', 'Getting started. Only deny rules and the security checks stop anything.']
            ] },
            { t: 'h', text: 'Audit only (learning mode)' },
            { t: 'p', text: 'With **Audit only** on, everything the rules would block is served anyway and recorded as "would have blocked". A request is opened for each package with the exact versions used. The kill switch still blocks in audit mode. Safe resolution, cooling off, license holds and lookalike blocking do not.' },
            { t: 'steps', items: [
              'Turn on **Audit only** in whitelist mode and point your pipelines at {{host}}.',
              'Let a few weeks of normal builds run.',
              'On **Requests**, approve what your teams really use. Tick several and use **Approve selected**.',
              'Check **Traffic** with **Show: would have blocked** until it is quiet.',
              'Turn **Audit only** off.'
            ] },
            { t: 'tip', text: 'Use **Dry run** before a big rule change to see who would be affected. See [Dry run](#docs/admin-dry-run).' }
          ]
        },
        {
          id: 'admin-rules-order', title: 'Writing rules',
          summary: 'Patterns, version ranges, priority and scope, and how the winning rule is chosen.',
          keywords: ['rules', 'allow rule', 'deny rule', 'pattern', 'glob', 'version range', 'semver', 'priority', 'precedence', 'which rule wins', 'prerelease'],
          blocks: [
            { t: 'shot', id: 'admin-rules' },
            { t: 'diagram', id: 'admin-rule-order', caption: 'Each step only matters when the step before it is a tie.' },
            { t: 'table', head: ['Field', 'Notes'], rows: [
              ['Pattern', 'A name or a pattern where `*` matches anything, including the `/` in a scope. Up to 5 wildcards.'],
              ['Kind', 'allow or deny. A deny with a version range only blocks those versions, the rest of the package still comes through.'],
              ['Version range', 'Empty means every version. See the table below.'],
              ['Priority', '-1000 to 1000, default 0. Compared first.'],
              ['Only for application / Only in environment', 'Limits the rule to tokens in that scope.'],
              ['Note', 'Why the rule exists. Shown to approvers, and worth writing.']
            ] },
            { t: 'table', head: ['Type', 'Version range examples'], rows: [
              ['npm', '`4.21.2`, `1.2.*`, `^4.0.0`, `~1.2.0`, `>=4.17.21`, `1.2.3 || 1.4.5`'],
              ['PyPI', '`==2.31.*`, `~=2.31.0`, `>=2.31,<3`, `>=2.31,!=2.32.1`'],
              ['images', '`latest`, `1.27.*`, `stable-alpine`, `sha256:...`, joined with `||`']
            ] },
            { t: 'list', items: [
              'npm deny rules match names in any letter case. Allow rules match the exact case.',
              'An allow covers a prerelease like `2.0.0-beta.1` only when its range names a prerelease. An allow with no range never covers prereleases.',
              '**Paste a list** adds up to 2000 names at once.',
              'Tick rules to flip, enable, disable or delete them together.'
            ] },
            { t: 'shot', id: 'admin-rules-list', caption: 'The rules list shows whether each rule is cached and whether its versions have advisories.' },
            { t: 'h', text: 'Caching approved versions ahead of time' },
            { t: 'p', text: 'Tick allow rules and click **Cache now** to download them before anyone needs them, up to 2000 files. A rule that pins exact versions caches those. A rule for any version caches the current release, and a range like `^4.0.0` caches the newest version it allows, without changing the rule. An image rule with a tag pattern like `1.27.*` is skipped. Saving an allow rule for every version also caches the current version in the background when **Cache the current version of any-version rules** is on.' },
            { t: 'note', text: 'For an image, **Cached** counts a tag only when every image in its list, and the config and every layer of each, is on disk. Walking an image\'s dependency tree or pulling one platform learns part of it, so the cell says how far along it is, like "26.04: 12 of 30 files downloaded". **Cache now** downloads the rest.' }
          ]
        },
        {
          id: 'admin-requests', title: 'Deciding requests',
          summary: 'Where requests come from and what approve, block and clear do.',
          keywords: ['requests', 'approve', 'block', 'clear', 'pending', 'auto request', 'approve dependencies', 'bulk approve'],
          blocks: [
            { t: 'p', text: 'Requests come from developers on the **Requests** page, and from installs that were blocked when **Open a request when an install is blocked** is on (Settings, Policy). Repeated blocks of the same package fold into one request and count up.' },
            { t: 'table', head: ['Action', 'What happens'], rows: [
              ['approve', 'Shows the dependency tree counts, asks for a note, then writes an allow rule for the name and the versions asked for.'],
              ['approve, with dependencies', 'Only when **Approving a request can approve its clean dependencies too** is on. Also approves up to 500 dependencies that nothing is known against, each pinned to its resolved version.'],
              ['block', 'Needs a reason. Writes a deny rule at priority 1000, for the versions asked for or the whole package.'],
              ['clear', 'Removes the request and writes nothing. If the install is blocked again, a new request appears.'],
              ['Approve selected / Clear selected', 'Decide many pending requests at once.']
            ] },
            { t: 'tip', text: 'Check the **Vulnerabilities** column before approving. It looks at the newest matching versions against the advisory feed.' }
          ]
        },
        {
          id: 'admin-auto-approve', title: 'Auto approve',
          summary: 'Let clean requests approve themselves, and keep anything risky for a person.',
          keywords: ['auto approve', 'automatic approval', 'approve automatically', 'hands off', 'self approve', 'clamav', 'advisories', 'high', 'critical'],
          blocks: [
            { t: 'p', text: 'Every request is checked as soon as it arrives: its files are downloaded, which caches them, scanned for malware, and looked up in the advisory feeds. On **Requests** each one says what the check found, like "checked: malware scan clean, no advisories", so you can decide at a glance.' },
            { t: 'p', text: 'With **Auto approve** on, a request that passes is approved by itself. Switch it on or off on the **Dashboard**, under **Auto approve**. Only admins can change it, a reason is required, admins are emailed, and the change goes into the audit trail.' },
            { t: 'table', head: ['The check finds', 'Auto approve does'], rows: [
              ['Every file scans clean for malware, and the worst advisory is below High', 'Approves it, pinned to the exact versions checked. The files are already cached.'],
              ['A High or Critical advisory', 'Leaves it in Requests for a person, naming the advisories.'],
              ['No malware answer: scanning off, a scanner down, or a file too big to scan', 'Leaves it for a person, saying why.'],
              ['A kill switch, a deny rule, a lookalike name, a reserved name, or a license held by the license rules', 'Leaves it for a person.'],
              ['A version still cooling off, a scan still running, or the registry in degraded or lockdown mode', 'Waits, and looks again every 5 minutes.']
            ] },
            { t: 'list', items: [
              'A request that names versions is approved for exactly those. A request with no version, which is what a blocked install makes, is approved for the whole package when **Scan before serving** is on, because every later version is still scanned before it is served. With **Scan before serving** off, it is pinned to the newest version that finished cooling off.',
              'For an image, every platform image, config and layer is downloaded and scanned, and the packages inside are checked. When **Only count what has a fix** is on, only advisories that have a fix count toward High and Critical.',
              'Malware scanning must be on with a content scanner such as ClamAV. A hash blocklist alone is not a scan.',
              'On **Requests**, a request auto approve would not take says **needs a person** and why, like "high advisories (CVE-2021-23337)". Approved rules say "auto approved" in their note, and the audit trail records **request.approve.auto**.',
              'While auto approve is on, an install refused for want of a rule tells the developer it is being checked and to try again in up to 10 minutes, or 30 for an image.'
            ] },
            { t: 'warn', text: 'Auto approve takes a person out of the loop for clean packages. Keep **Cooling off** on, so a brand new malicious release is not approved in its first hours, before scanners and advisory feeds know about it.' }
          ]
        },
        {
          id: 'admin-waivers', title: 'Deciding waivers',
          summary: 'Let a version through a vulnerability, license or cooling off check for a limited time.',
          keywords: ['waiver', 'exception', 'grant waiver', 'advisory waiver', 'license waiver', 'cooling off waiver', 'expire', 'waiver max days'],
          blocks: [
            { t: 'shot', id: 'admin-waivers' },
            { t: 'table', head: ['Kind', 'Lets through', 'Rules'], rows: [
              ['A known advisory', 'A version refused by safe version resolution', 'Must name every advisory on the version. A new advisory brings the block back.'],
              ['A license', 'A version held for its license', 'Applies to everyone. Matches the exact license expression.'],
              ['Cooling off', 'A version still inside the cooling off period', 'Any matching waiver.']
            ] },
            { t: 'list', items: [
              'Waivers last 1 day up to **Longest waiver, in days** (default 90, at most 365).',
              '**approve** or **reject** a waiting waiver. **revoke** ends one in effect. Expired waivers move to **Finished** within a minute.',
              '**Grant it now** skips the wait, and is recorded against your name.',
              'Kills, malware results and integrity alerts can never be waived.'
            ] }
          ]
        },
        {
          id: 'admin-dry-run', title: 'Dry run a change before you make it',
          summary: 'Replay recent downloads against a new rule, vulnerability threshold or license list.',
          keywords: ['dry run', 'what if', 'impact', 'simulate', 'test rule', 'preview change', 'blast radius'],
          blocks: [
            { t: 'p', text: '**Dry run** replays up to 90 days of downloads against a proposed change and shows who would be affected. Nothing is saved.' },
            { t: 'shot', id: 'admin-dryrun' },
            { t: 'list', items: [
              '**A new rule**: a deny counts downloads allowed today that it would refuse. An allow counts downloads refused today that it would let through.',
              '**Leave out vulnerable versions**: tries a safe resolution threshold, respecting waivers.',
              '**Different license lists**: tries new allowed, review and blocked lists.'
            ] },
            { t: 'p', text: 'Results list packages, versions, applications (and how many are production), developers, CI pipelines and downloads without a token.' }
          ]
        }
      ]
    },
    // ================================================================================================ protections
    {
      id: 'protect', label: 'Security protections',
      topics: [
        {
          id: 'admin-safe-resolution', title: 'Vulnerabilities and safe version resolution',
          summary: 'Keep known vulnerable versions out of installs automatically.',
          keywords: ['vulnerabilities', 'cve', 'osv', 'safe resolution', 'severity', 'kev', 'epss', 'npm audit', 'advisory', 'scan'],
          blocks: [
            { t: 'p', text: '{{name}} checks cached and approved versions against osv.dev on a schedule (**Hours between scans of the allow list**, default 24), and checks a new version when it is first downloaded. CISA KEV and FIRST EPSS add whether an advisory is exploited in the wild and how likely it is to be.' },
            { t: 'shot', id: 'admin-vulnerabilities', caption: 'Settings for container image scanning sit on the Vulnerabilities page.' },
            { t: 'h', text: 'Telling developers' },
            { t: 'list', items: [
              '**Answer npm audit**: `npm audit` gets its answer from these findings. The dependency tree never leaves the box.',
              '**Warn during the install**: npm prints the advisory as the package installs.',
              '**Record who downloaded what**: every download of a vulnerable version is logged with the token and application.'
            ] },
            { t: 'h', text: 'Safe version resolution' },
            { t: 'p', text: 'Nothing on the Vulnerabilities page blocks by itself. Turn on **Safe version resolution** (Settings, Policy) and pick **Leave out advisories from** (default HIGH). Versions at or above that severity are then left out of metadata, so npm and pip pick the newest safe version within the range, and an exact download of one is refused with the advisory named.' },
            { t: 'list', items: [
              '**Also leave out what is exploited in the wild** (on by default): a version whose advisory CISA lists as known exploited (KEV) is left out whatever its severity, even an unrated one.',
              '**Also leave out likely exploits, EPSS from**: a version whose advisory has at least this EPSS score is left out too, like `10%`. Empty is off.',
              'Both need the threat intelligence feeds on (Integrations), and the reason a developer is told names KEV or EPSS.'
            ] },
            { t: 'note', text: 'Advisories with an unknown severity are only left out when KEV or EPSS say so. A waiver for the exact advisories lets a version back in. The **Resolutions** page shows what was left out and what the client picked instead.' }
          ]
        },
        {
          id: 'admin-cooling-off', title: 'Cooling off new releases',
          summary: 'Hold brand new versions for a few days, when most malicious releases are caught.',
          keywords: ['cooling off', 'cooloff', 'quarantine new versions', 'delay', 'minimum age', 'fresh release'],
          blocks: [
            { t: 'p', text: 'Most malicious releases are found and pulled within days. **Cooling off, in hours** (Settings, Policy, default 0 which is off) hides versions younger than that from metadata and refuses them by URL. Developers get "published 3 hours ago, new versions wait 72 hours (served from ...)".' },
            { t: 'list', items: [
              '**Never cooled off**: name patterns that skip the wait, like `@acme/*`.',
              '**A version with no publish time**: `allow` (default) or `hold`.',
              'An allow rule that pins the exact version skips the wait, and so does a cooling off waiver.',
              'Audit mode turns cooling off off.'
            ] },
            { t: 'tip', text: '72 hours is a common choice. Pair it with a cooling off waiver process for urgent security fixes.' }
          ]
        },
        {
          id: 'admin-malware', title: 'Malware scanning',
          summary: 'Scan every downloaded file with a hash blocklist, ClamAV, the known-malicious feed or your own scanner.',
          keywords: ['malware', 'clamav', 'antivirus', 'scanner', 'blocklist', 'hash', 'rest scanner', 'osv', 'known malicious', 'MAL-', 'openssf', 'malicious packages', 'auto kill', 'scan before serve', 'malicious', 'suspicious', 'size limit', 'StreamMaxLength', 'too big', 'clamd.conf', '429', 'large layer'],
          blocks: [
            { t: 'p', text: 'Settings, **Malware** tab. Tick **Scan cached files** and pick **Scanners**:' },
            { t: 'table', head: ['Scanner', 'How it works'], rows: [
              ['blocklist', 'A list of sha256 hashes you maintain. A match is MALICIOUS.'],
              ['clamav', 'Streams each file to your clamd over TCP. Start the bundled one with `COMPOSE_PROFILES=clamav`.'],
              ['osv', 'Asks osv.dev whether the exact package and version is a known-malicious one (the OpenSSF malicious packages feed, advisories named MAL-). A hit is MALICIOUS. Only the name and version leave the box, never the file. It catches what a signature scanner has no pattern for, but it only knows what has been reported, so keep a content scanner too.'],
              ['secrets', 'Reads inside every file kept here, the layers of a pushed image included, and calls one carrying a private key, a cloud or registry token or a .env SUSPICIOUS. The finding names the file and the kind, never the value. Public packages carry test keys by the thousand, so this is off unless you put it on the list. What is published here is read this way at push time whatever the scanner list says.'],
              ['rest', 'Posts each file to your scanner, which answers with a status such as CLEAN or MALICIOUS.']
            ] },
            { t: 'list', items: [
              '**When a scanner says MALICIOUS**: reject (default), hold or warn.',
              '**When a scanner says SUSPICIOUS**: hold (default), warn or ignore.',
              '**Scan before serving**: a file is not served until every content scanner has an answer. If that takes over 60 seconds the client gets a 503 and tries again.',
              'If ClamAV is down, files it already passed are still served and new ones wait. They are scanned as soon as clamd answers again, and the ClamAV watchdog setup.sh installs restarts a clamd that has stopped answering.',
              'A clean rescan releases the scanner\'s own holds, but never undoes a person\'s decision.',
              '**Kill known-malicious packages by themselves** (on by default): when the scheduled vulnerability scan finds a MAL- advisory against anything here, that advisory goes on the kill switch at once and admins get the kill switch mail. It is added once. If an admin lifts it, the next scan leaves it lifted.'
            ] },
            { t: 'p', text: 'The **Scanner status** box shows whether each scanner is ready, and has **Scan what has not been scanned**, **Rescan everything** and **Stop**.' },
            { t: 'warn', text: 'ClamAV refuses files bigger than its own limits, and with **Scan before serving** on, a file ClamAV refuses is never served. Out of the box clamd stops at 100 MB, smaller than many container image layers and some Python wheels. The bundled ClamAV reads `docker/clamd.conf`, which raises the limits to 4000M. If you run your own clamd, set these in its `clamd.conf`:' },
            { t: 'code', file: 'clamd.conf', text: 'StreamMaxLength 4000M\nMaxScanSize 4000M\nMaxFileSize 4000M' },
            { t: 'p', text: 'A file that was too big shows "too big for clamd" in its scan result, and developers are told an admin has to raise the scanner size limit. Once the limit is raised, the next download scans it again.' }
          ]
        },
        {
          id: 'admin-quarantine-integrity', title: 'Quarantine and integrity alerts',
          summary: 'Files held for review, and files whose contents changed after they were first seen.',
          keywords: ['quarantine', 'hold', 'release', 'reject', 'strict', 'permissive', 'integrity', 'tampered', 'changed bytes', 'republished'],
          blocks: [
            { t: 'shot', id: 'admin-quarantine' },
            { t: 'p', text: 'A file is held when malware scanning, provenance, license rules, an integrity alert, a person, or a new publish says it needs a look. **Quarantine** (Settings, Policy) decides what developers get meanwhile:' },
            { t: 'table', head: ['Mode', 'Held files'], rows: [
              ['permissive (default)', 'Still served, with a QUARANTINE warning printed by npm.'],
              ['strict', 'Refused with a 403 and left out of metadata.'],
              ['any mode', 'Rejected files are always refused.']
            ] },
            { t: 'p', text: '**release** serves the file normally. **reject** refuses it for good. Holds belong to the file itself, so purging and downloading it again does not escape one.' },
            { t: 'h', text: 'Integrity alerts' },
            { t: 'p', text: 'The first copy of a file wins. If npm or PyPI later publish a different hash for the same version, or a download returns different bytes, {{name}} raises an integrity alert, holds the file and keeps serving the original bytes. On **Integrity alerts**, **accept** takes the new file and **keep original** dismisses the alert.' },
            { t: 'warn', text: 'A changed file for a version that was already published is a classic sign of a compromised registry account. Check before you accept.' }
          ]
        },
        {
          id: 'admin-licenses-provenance', title: 'Licenses, lookalikes and provenance',
          summary: 'License rules, typosquat detection, and signed build provenance.',
          keywords: ['license', 'gpl', 'agpl', 'spdx', 'license enforcement', 'typosquat', 'lookalike', 'provenance', 'sigstore', 'slsa', 'attestation'],
          blocks: [
            { t: 'h', text: 'Licenses' },
            { t: 'p', text: 'Settings, `Licenses` tab. **What to do about it**: off, warn or enforce. Under enforce, a license on the **Needs review** list is held for review and one on **Blocked** is held and rejected. For `MIT OR GPL-3.0` the most permissive part counts. For `AND` the strictest part counts.' },
            { t: 'h', text: 'Lookalike packages' },
            { t: 'p', text: '**Typosquat checks** (warn, block or off) compare new names against popular packages and your own busiest ones, looking for swapped letters, look alike characters like `0` for `o`, extra words like `-js`, and scope tricks. Warn prints a TYPOSQUAT notice, block refuses. In whitelist mode an unknown name is already refused by the rules first. The **Lookalike packages** page lists findings and lets you mark one **not a typosquat**.' },
            { t: 'h', text: 'Provenance' },
            { t: 'p', text: 'For npm and PyPI, {{name}} verifies Sigstore signed build provenance against the exact file it holds. Results are VERIFIED, PRESENT_UNVERIFIED, MISSING or INVALID, shown on **Artifacts**. **When provenance is INVALID**: warn (default) or hold.' },
            { t: 'p', text: '**When a release starts running code at install** (warn by default): an npm version with a new preinstall, install or postinstall script or a binding.gyp in its tarball, or a PyPI release with no wheel after ones that had wheels. **When an npm listing disagrees with its tarball** (hold by default): npm installs from the tarball, so a listing that hides an install script or a dependency is held; a different license, bin or peer dependency only warns.' },
            { t: 'p', text: '**When a release looks like a takeover** (warn by default): published by somebody new to that package, a maintainer joining or leaving with it, or a year of quiet before it. Ordinary enough on their own, so they are recorded and mailed rather than held unless you set it to hold.' },
            { t: 'p', text: '**When provenance goes backward** (hold by default): a new version with no provenance when an older one had verified provenance, or with verified provenance from a different source repository, is held. That is what a stolen publishing token usually looks like. Release it on **Quarantine** once the maintainers confirm the release.' }
          ]
        }
      ]
    },
    // ================================================================================================ images and publishing
    {
      id: 'images-publish', label: 'Images and publishing',
      topics: [
        {
          id: 'admin-nuget', title: 'NuGet feeds', ecosystem: 'nuget',
          summary: 'Mirror nuget.org or a private feed for dotnet and Visual Studio, with the same checks as npm and PyPI.',
          keywords: ['nuget', 'dotnet', '.net', 'nuget.org', 'azure artifacts', 'github packages', 'nuget rules', 'X-NuGet-Warning', 'nupkg'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **NuGet feed**.',
              'Add a NuGet registry. For nuget.org use `https://api.nuget.org/v3/index.json`. For Azure Artifacts or GitHub Packages use the feed\'s `index.json` address and a token written as `username:personal-access-token`.',
              'Write NuGet rules: pattern `Newtonsoft.Json` or `Microsoft.Extensions.*`, versions `13.0.3`, `[13.0,14.0)`, `13.*`, or nothing for any version.',
              'Developers add **{{origin}}/nuget/v3/index.json** to their `nuget.config`. See [Set up dotnet](#docs/nuget-setup).'
            ] },
            { t: 'list', items: [
              'A package id is one package in any case. Rules and kills match `newtonsoft.json` and `Newtonsoft.Json` alike, and the box keeps the spelling the feed uses, which the advisory feed needs.',
              'A bare version in a rule is that exact version. NuGet itself reads `13.0` as "13.0 or newer", so write `[13.0,)` for that.',
              'dotnet shows why a package was refused. The reason goes out in the `X-NuGet-Warning` header, and dotnet prints it as a warning.',
              'Every package is scanned for malware, checked against the OSV advisories, has its SPDX license read, and waits out cooling off, the same as npm and PyPI. Auto approve and **Cache now** work for NuGet rules too.',
              'The feed offers the package list, downloads and `dotnet nuget push` to reserved package ids. Search is not offered yet.'
            ] },
            { t: 'shot', id: 'admin-nuget-rules', caption: 'NuGet rules with the NuGet mark. Cached counts the versions kept here.' }
          ]
        },
        {
          id: 'admin-maven', title: 'Maven repositories', ecosystem: 'maven',
          summary: 'Mirror Maven Central or a private repository for mvn, Gradle and sbt, with the same checks as the other types.',
          keywords: ['maven', 'maven central', 'gradle', 'nexus', 'artifactory', 'jar', 'pom', 'maven rules', 'plugins', 'sha1'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **Maven repository**.',
              'Add a Maven registry. For Maven Central use `https://repo1.maven.org/maven2`. For Nexus or Artifactory use the repository address and a token written as `username:password`.',
              'Write Maven rules on `groupId:artifactId`. A `*` works anywhere, like `org.apache.maven.plugins:*`. Versions take `2.17.2`, `[2.17,2.18)` or `2.17.*`.',
              'Developers add a mirror to `settings.xml`. See [Set up Maven](#docs/maven-setup).'
            ] },
            { t: 'list', items: [
              'mvn downloads its own plugins through the same repository, so a new box needs allow rules for them. `org.apache.maven*`, `org.codehaus.plexus*` and friends cover the usual ones. Audit mode shows the full list after one build.',
              'Every file is checked against the `.sha1` the repository publishes before it is kept. A file that does not match is refused.',
              'The version list (`maven-metadata.xml`) holds only allowed versions, so a range resolves to an allowed one.',
              'A milestone or release candidate like `5.11.0-M2` counts as an ordinary version, because poms pin them exactly. Snapshots are never served.',
              'Every file is scanned for malware, checked against OSV, has its pom license read, and waits out cooling off. Auto approve and **Cache now** work for Maven rules too.',
              '`mvn deploy` deploys releases to reserved coordinates. Each file is held until it is scanned, a deployed file never changes, checksum files are checked against what arrived rather than kept, and the version list is built here from what was deployed. Snapshots are refused.'
            ] }
          ]
        },
        {
          id: 'admin-rubygems', title: 'Gem sources', ecosystem: 'rubygems',
          summary: 'Mirror rubygems.org or a private gem source for Bundler and gem install, with the same checks as the other types.',
          keywords: ['rubygems', 'gem', 'bundler', 'rubygems.org', 'gemfury', 'compact index', 'gem rules', 'checksum', '451'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **RubyGems source**.',
              'Add a RubyGems registry. For rubygems.org use `https://rubygems.org`.',
              'Write gem rules: pattern `rack` or `rails-*`, versions `3.1.8`, `~> 3.1` or `>= 3.0, < 4`.',
              'Developers set a Bundler mirror. See [Set up Bundler](#docs/bundler-setup).'
            ] },
            { t: 'list', items: [
              'Every gem has to match the sha256 its source lists for it. A gem with no listed checksum, or a different one, is refused and not kept.',
              'The version list a gem gets (`/info`) holds only allowed versions, so Bundler resolves to an allowed one.',
              'Bundler looks at the version list of every gem it might need, old versions included. A gem with nothing allowed shows no versions, so the resolver picks versions that do without it. Only a download of an unapproved gem opens a request.',
              'A refused download is answered with a 451 status, the one Bundler prints the reason for.',
              'Every gem is scanned for malware, checked against OSV, has its license read from rubygems.org, and waits out cooling off. Auto approve and **Cache now** work for gem rules too.',
              '`gem push` pushes to reserved gem names. The gemspec `gem install` asks for is written here from the gem itself, so installing a pushed gem works the way it does from rubygems.org. `gem yank` is refused: push a new version instead.'
            ] }
          ]
        },
        {
          id: 'admin-cocoapods', title: 'CocoaPods CDNs', ecosystem: 'cocoapods',
          summary: 'Mirror the CocoaPods CDN for pod install. The code of each pod is fetched and scanned by this box.',
          keywords: ['cocoapods', 'pod', 'cdn.cocoapods.org', 'podspec', 'ios', 'pod rules', 'github', 'source archive'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **CocoaPods CDN**.',
              'Add a CocoaPods registry. For the public pods use `https://cdn.cocoapods.org`.',
              'Write pod rules: pattern `Alamofire` or `Firebase*`, versions `5.9.1` or `~> 5.9`.',
              'Developers add the source line to their Podfile. See [Set up CocoaPods](#docs/pod-setup).'
            ] },
            { t: 'list', items: [
              'The CDN only describes a pod. Its code is a git tag, usually on GitHub. {{name}} fetches the tag archive itself, keeps and scans it, and the podspec it hands out points pod at that copy.',
              'A pod whose code cannot be fetched as a fixed archive is refused: a git branch or commit, git submodules, svn, or a download that does not match the checksum in its podspec. Sources on an internal address are never fetched.',
              'The version lists hold only allowed pods and versions, so a pod nobody approved is not found. Only a download of an unapproved version opens a request.',
              'OSV has no CocoaPods feed, so pods get no advisories. Malware scanning, licenses, the kill switch, auto approve and **Cache now** all work.',
              'A podspec can hold a `prepare_command`, a shell command pod runs on the developer\'s machine. Approving a pod approves that too.'
            ] }
          ]
        },
        {
          id: 'admin-swift', title: 'Swift package registry', ecosystem: 'swift',
          summary: 'Answer SwiftPM as a package registry over a git host. Each version tag is fetched once, kept and scanned.',
          keywords: ['swift', 'swiftpm', 'package registry', 'github', 'git host', 'tags', 'SwiftURL', 'swift rules'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **Swift package registry**.',
              'Add a Swift registry. Its address is a git host, like `https://github.com`.',
              'Write Swift rules: pattern `apple.swift-log` or `apple.*`, versions `1.6.1`, `^1.6.0` or `>=1.6 <2`.',
              'Developers point SwiftPM at `/swift/`. See [Set up SwiftPM](#docs/swift-setup).'
            ] },
            { t: 'list', items: [
              'A package is a repository. `apple.swift-log` is `github.com/apple/swift-log`. Its tags that are versions, like 1.6.1 or v1.6.1, are its releases.',
              'The tag list comes from git itself, not the GitHub API, so there is no API rate limit.',
              '{{name}} fetches the tag archive once, keeps and scans it, and gives SwiftPM its checksum. A tag moved later on the git host changes nothing here.',
              'While it resolves, SwiftPM reads the manifest of several allowed versions, not only the one it picks. Each of those archives is fetched and kept too, because the manifest and the checksum come from it.',
              'The release list holds only allowed versions. A package with none allowed is refused with the reason, and that opens a request.',
              'Advisories come from OSV, which knows Swift packages by their GitHub url. Malware scanning, the kill switch, auto approve and **Cache now** all work.',
              'Package.swift names no license, so Swift packages have none on record.',
              '`swift package-registry publish` is refused. This registry mirrors packages.'
            ] }
          ]
        },
        {
          id: 'admin-composer', title: 'Composer repositories', ecosystem: 'composer',
          summary: 'Mirror Packagist for composer. The archive of each release is fetched and scanned by this box.',
          keywords: ['composer', 'php', 'packagist', 'repo.packagist.org', 'composer rules', 'dist', 'zip'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **Composer repository**.',
              'Add a Composer registry. For the public packages use `https://repo.packagist.org`.',
              'Write Composer rules: pattern `monolog/monolog` or `symfony/*`, versions `3.5.0`, `^3.5` or `>=3.5 <4.0`.',
              'Developers add the repository and turn Packagist off. See [Set up Composer](#docs/composer-setup).'
            ] },
            { t: 'list', items: [
              'The metadata lists only allowed releases. A package with none allowed is not found, and that opens a request.',
              'Each release points at one exact commit. {{name}} fetches that commit\'s zip once, keeps and scans it, and the metadata it hands out points composer at that copy.',
              'The git source of each release is taken out, so composer can not fall back to cloning it.',
              'A release that can not be fetched as a fixed zip is left out: one with only a git source, one pinned to a branch, or a tarball. An archive on an internal address is never fetched.',
              'Advisories come from OSV. Malware scanning, licenses, the kill switch, auto approve and **Cache now** all work.',
              'Branches (dev versions) are not served.'
            ] }
          ]
        },
        {
          id: 'admin-rpm', title: 'RPM mirrors', ecosystem: 'rpm',
          summary: 'Mirror distro repositories like AlmaLinux 9 BaseOS for dnf and yum. Every package is checked and scanned.',
          keywords: ['rpm', 'dnf', 'yum', 'mirror', 'almalinux', 'rocky', 'rhel', 'repomd', 'filtered index', 'repo_gpgcheck', 'ALSA', 'RLSA'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **RPM mirror**.',
              'Add an RPM registry for each repository. Its address is the folder that holds repodata/, like `https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os`.',
              'Pick the advisory feed of its distro, like AlmaLinux:9, so its packages are checked against the right advisories.',
              'In whitelist mode, add an RPM allow rule of `*`, then deny or kill what you do not want. A distro has thousands of packages.',
              'Developers use the address the mirror shows, like `/rpm/almalinux-9-baseos/`. See [Set up dnf and yum](#docs/rpm-setup).'
            ] },
            { t: 'list', items: [
              'By default the index goes out exactly as the distro signed it, so clients keep checking its signature. Every download is checked: the rules, the kill switch, holds, advisories and cooling off.',
              'With **Filtered index** on, the index lists only what the rules and the kill switch allow, so dnf never picks a refused version. The distro did not sign that index, so clients must set `repo_gpgcheck=0`. Package signatures are still checked.',
              'Every package is checked against the checksum in the repository index before it is kept, and every metadata file against the checksum in repomd.xml.',
              'Only the repodata and the packages the index lists are served. Nothing else of the tree is.',
              'Advisories come from OSV, in the feed you picked for the mirror: ALSA for AlmaLinux, RLSA for Rocky Linux, RHSA for Red Hat.'
            ] }
          ]
        },
        {
          id: 'admin-apt', title: 'APT mirrors', ecosystem: 'apt',
          summary: 'Mirror Debian and Ubuntu archives for apt. Every package is checked and scanned.',
          keywords: ['apt', 'debian', 'ubuntu', 'mirror', 'InRelease', 'filtered index', 'signing key', 'DSA', 'USN'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **APT mirror**.',
              'Add an APT registry for each archive. Its address is the archive root, like `https://deb.debian.org/debian`. Security updates are their own archive, like `https://security.debian.org/debian-security`.',
              'Pick the advisory feed of its distro, like Debian:12, so its packages are checked against the right advisories.',
              'In whitelist mode, add an APT allow rule of `*`, then deny or kill what you do not want.',
              'Developers use the address the mirror shows, like `/apt/debian/`. See [Set up apt](#docs/apt-setup).'
            ] },
            { t: 'list', items: [
              'By default each suite\'s InRelease goes out exactly as the distro signed it, and every download is checked: the rules, the kill switch, holds, advisories and cooling off.',
              'With **Filtered index** on, {{name}} first checks the distro\'s signature itself, then hands out Packages files of only what the rules and the kill switch allow, for amd64 and arm64, signed with its own key. Clients trust that key with signed-by. This works for the official Debian and Ubuntu archives.',
              'Every index file is checked against the SHA256 in InRelease, and every .deb against the SHA256 in its Packages file, before it is kept.',
              'Advisories come from OSV, in the feed you picked, by source package: libssl3 gets the advisories of openssl.',
              'The signing key is made on first use and kept in the cache folder. If it is ever lost, every client has to fetch the new one.'
            ] }
          ]
        },
        {
          id: 'admin-images', title: 'Container images',
          summary: 'Mirror images from Docker Hub and other registries, scan what is inside, and refuse vulnerable ones.',
          keywords: ['docker', 'container images', 'oci', 'image scanning', 'scan before serve', 'fixable', 'docker hub', 'image rules', 'digest'],
          blocks: [
            { t: 'steps', items: [
              'Settings, Registries: switch on **container images**.',
              'Add an image registry. For Docker Hub use `https://registry-1.docker.io` and a token written as `username:access-token` to avoid anonymous pull limits.',
              'Write image rules: pattern `nginx`, versions `stable-alpine || 1.27.*`.',
              'Developers pull `{{dockerHost}}/nginx:stable-alpine`.'
            ] },
            { t: 'list', items: [
              'On Docker Hub, `nginx` and `library/nginx` are the same image, and a deny or kill on either covers both.',
              'A tag is checked on every pull. A digest is only served when a tag the rules allow points at it, so a denied tag cannot be pulled by digest.',
              'Refused tag pulls open a request. Digest pulls do not.',
              'Publishers can push images under reserved names. See [Reserved names and publishing](#docs/admin-reserved-publishing).'
            ] },
            { t: 'h', text: 'Image scanning' },
            { t: 'p', text: 'With **Scan the images people pull** on, each pulled image is read layer by layer to list the operating system packages and the npm and Python packages inside, then checked against the advisories for Debian, Ubuntu, Alpine, Wolfi, Chainguard, Red Hat, Rocky and AlmaLinux.' },
            { t: 'list', items: [
              '**Scan before serving**: an image nobody has scanned yet answers "try again in a minute" until the scan finishes.',
              '**Only count what has a fix**: refusals only count advisories an upgrade fixes.',
              'Refusals only happen with **Safe version resolution** on. A waiver on the digest or any of its tags lets the image through.'
            ] },
            { t: 'shot', id: 'dependency-tree-image', caption: 'The dependency tree of an image: platforms, layers and packages.' }
          ]
        },
        {
          id: 'admin-image-signatures', title: 'Image signatures', ecosystem: 'oci',
          summary: 'Only serve images signed with cosign by a key or a signer you trust.',
          keywords: ['cosign', 'sigstore', 'signature', 'signed images', 'keyless', 'fulcio', 'rekor', 'transparency log', 'trust policy', 'supply chain', 'github actions', 'verify'],
          blocks: [
            { t: 'p', text: 'Settings, Registries, **Image signatures**. A trust policy names repositories and who has to have signed their images. It is checked on every manifest pull, pulled or pushed, from Docker Hub or anywhere else.' },
            { t: 'table', head: ['Field', 'What it takes'], rows: [
              ['Repository', 'An exact name like `library/nginx` or `acme/api`, a namespace like `acme/*`, or a prefix ending in `*`. The most specific policy wins.'],
              ['Mode', '**require** refuses an image nobody trusted signed. **warn** lets it through and logs it in Traffic.'],
              ['Trusted public keys', 'PEM public keys, like the `cosign.pub` that `cosign generate-key-pair` writes. ECDSA, Ed25519 and RSA.'],
              ['Trusted keyless signers', 'One per line: the issuer, a space, the subject. `https://token.actions.githubusercontent.com https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main` trusts one workflow. A `*` can end an address with its owner in it, like `https://github.com/acme/*`, or stand for the name in an email, like `*@acme.com`.'],
              ['Transparency log', 'Keyless signatures always need their Rekor entry. Tick it to need one for keyed signatures too.']
            ] },
            { t: 'list', items: [
              'Signatures are read from the `sha256-<digest>.sig` tag cosign 2 writes, and from the Sigstore bundle cosign 3 writes under the referrers tag `sha256-<digest>`. Either passes. They are kept here, so they answer offline too.',
              'Keyless signatures are checked against the Sigstore public good Fulcio roots and Rekor log keys shipped with {{name}}. The certificate chain the signer attaches is never trusted by itself.',
              'A signed multi-platform list covers the platform images it names.',
              'A signature found missing or wrong is asked for again after ten minutes, so an image signed after its first pull passes.',
              'Changing or removing a policy takes effect within 30 seconds, and every change is in the audit trail.',
              'In audit mode nothing is refused, unsigned pulls are only logged.'
            ] },
            { t: 'code', file: 'sign an image you push here', text: 'cosign sign --key cosign.key {{dockerHost}}/acme/api@sha256:<digest>' }
          ]
        },
        {
          id: 'admin-reserved-publishing', title: 'Reserved names and publishing',
          summary: 'Protect internal package names from dependency confusion and let CI publish them.',
          keywords: ['reserved names', 'private packages', 'dependency confusion', 'internal packages', 'publish', 'npm publish', 'twine', 'scope', '@acme',
            'docker push', 'push images', 'namespace', '413', 'client_max_body_size', 'request entity too large'],
          blocks: [
            { t: 'diagram', id: 'admin-confusion', caption: 'A reserved name is only ever served from what was published here.' },
            { t: 'steps', items: [
              'Settings, Registries, **Reserved names**: add `@acme/*` for npm, `acme-*` for PyPI, `acme/*` for Docker and `Acme.*` for NuGet.',
              'Give your release pipeline a user with the **publisher** role and a token.',
              'Add an allow rule for the same names. In whitelist mode even your own packages need one.',
              'Publish with `npm publish`, `twine upload`, `docker push` or `dotnet nuget push`. See the developer topics on publishing and [pushing images](#docs/image-push).'
            ] },
            { t: 'shot', id: 'admin-reserved-names', caption: 'Reserved names for npm, PyPI and Docker. Pick Docker under Type to reserve an image namespace.' },
            { t: 'list', items: [
              'A reserved name is never fetched from any upstream, even if a public copy was cached before you reserved it.',
              'Only reserved names can be published. Versions never change and cannot be unpublished. Use `npm deprecate` instead.',
              'New publishes are held. With malware scanning on, a clean scan releases them. Otherwise an admin releases them on **Quarantine**. In permissive mode they are served meanwhile with a warning.',
              'A package built to trick whatever unpacks it is refused: a path that climbs out with `..` or starts at `/`, a link, a device file, the same name twice, or a zip whose two directories name a file differently.',
              'A package that looks like it carries a secret (a private key, an AWS, GitHub, GitLab, npm, PyPI, NuGet, Slack, Stripe, Google or Azure key, a ForgeRepo token, a password in a connection string, a `.env`, an `.npmrc` or `.pypirc` with a login, an SSH key, a `.p12`) gets a **hygiene** hold. That hold refuses in both quarantine modes and is never lifted by a clean scan. Rotate whatever leaked, then release it on **Quarantine** only if the findings are not real. The finding names the file and the kind of secret, never the secret. **Secrets in what is published here** (Settings, Policy) can make it warn only, or switch it off.'
            ] },
            { t: 'h', text: 'Pushed images' },
            { t: 'list', items: [
              'A pushed image is held until every layer is scanned clean, in both quarantine modes. With scanning off, release it on **Quarantine**.',
              'A pushed tag never moves, except `latest`. Nothing pushed can be deleted through the registry.',
              'Once any image name is reserved, docker is asked to sign in when it first connects. That is how it learns to send its login when it pushes. With **Require a token from package managers** off, docker still pulls without a login: it gets an anonymous token and carries on.',
              'An upload belongs to the person who started it. Nobody else can add to it, finish it or read how far it got.'
            ] },
            { t: 'shot', id: 'admin-artifacts-pushed', caption: 'The layers of a pushed image in Artifacts, approved once each one scanned clean.' },
            { t: 'h', text: 'Big layers and the reverse proxy' },
            { t: 'p', text: 'docker push sends each layer as one request, often hundreds of megabytes. A proxy with a small body limit answers `413 Request Entity Too Large` and docker keeps retrying. Give the upload path its own limit and let it stream straight through:' },
            { t: 'code', file: 'nginx', text: 'location ~ ^/v2/.+/blobs/uploads/ {\n    client_max_body_size 10g;\n    proxy_request_buffering off;\n    proxy_read_timeout 3600s;\n    proxy_send_timeout 3600s;\n    proxy_pass http://127.0.0.1:4444;\n    proxy_http_version 1.1;\n    proxy_set_header Host              $host;\n    proxy_set_header X-Forwarded-For   $remote_addr;\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_set_header X-Forwarded-Host  $host;\n}' },
            { t: 'p', text: 'The example in `nginx/npm-repo.conf.example` has it already. A layer can be up to 10 GB.' }
          ]
        }
      ]
    },
    // ================================================================================================ incidents
    {
      id: 'incidents', label: 'Incident response',
      topics: [
        {
          id: 'admin-kill-switch', title: 'The kill switch',
          summary: 'Stop a malicious package everywhere at once and find everyone who has it.',
          keywords: ['kill switch', 'kill', 'malicious package', 'compromised', 'incident', 'emergency', 'block everywhere', 'who pulled it', 'purge', 'lift', 'csv', 'bulk', 'upload', 'supply chain attack', 'campaign', 'hundreds'],
          blocks: [
            { t: 'diagram', id: 'admin-incident' },
            { t: 'shot', id: 'admin-killswitch' },
            { t: 'table', head: ['Kill', 'Stops'], rows: [
              ['A package', 'Every version, or a range, tag or digest you name. Exact names only.'],
              ['One file, by its sha256', 'That exact file under any name, including copies that turn up later.'],
              ['An advisory', 'Every version the vulnerability scan has recorded against a CVE, GHSA or PYSEC id.']
            ] },
            { t: 'h', text: 'Hundreds at once, from a CSV' },
            { t: 'p', text: 'When an advisory lists a whole campaign, admins can use **Kill from a CSV**. One row per package: package, version, type. Type is npm, pypi (or python) or oci (or docker). An empty version kills every version.' },
            { t: 'code', file: 'campaign.csv', text: 'package,version,type\nevent-stream,3.3.6,npm\nua-parser-js,0.7.29 || 0.8.0 || 1.0.0,npm\nrequests,==2.31.0,pypi\nlibrary/nginx,1.25.3,docker\nflatmap-stream,,npm' },
            { t: 'steps', items: [
              'Pick the file or paste the rows, and write the reason.',
              'Click **Check the file**. The list shows every package, which are already killed, and each row that cannot be read with its line number. Nothing is killed yet.',
              'Click **Kill N package(s)** and confirm. Rows for the same package become one kill. Admins get one email with the list, and each kill is in the audit trail.'
            ] },
            { t: 'steps', items: [
              'Open **Kill switch** and fill in **Kill something**. The reason is shown to every developer who is refused, so say what to use instead.',
              'Tick **Also delete the cached copies now** if the files must not stay on disk.',
              'Click **Kill it**. It takes effect within seconds, beats every allow rule, scope and waiver, and works in audit mode.',
              'Use **who pulled it** for the last 30 days of downloads by token, application, environment and address. Admins and approvers also get this by email.',
              'Use **Consumers** for the longer history and a per application SBOM.',
              'When it is safe, **lift** the kill with a note.'
            ] }
          ]
        },
        {
          id: 'admin-consumers', title: 'Consumers and SBOMs',
          summary: 'Answer "who uses this package" and export a bill of materials per application.',
          keywords: ['consumers', 'who uses', 'sbom', 'cyclonedx', 'spdx', 'bill of materials', 'inventory', 'blast radius'],
          blocks: [
            { t: 'p', text: 'Search **Consumers** by package name, file sha256 or advisory id. Results show every application, environment, developer, pipeline and address that downloaded it, with first and last dates.' },
            { t: 'shot', id: 'admin-consumers' },
            { t: 'p', text: 'Under **SBOM of an application**, pick an application and environment and export **CycloneDX** or **SPDX**, built from what that application actually downloaded. How long this history is kept is **Days to remember who consumed what** (Settings, Cache, default 365).' },
            { t: 'list', items: [
              'Every package type is included, each with its own purl, from npm and PyPI to Maven, NuGet, gems, Composer, CocoaPods, Swift, RPM, APT and images.',
              'Each image the application pulled lists the packages found inside it: OS packages with their distro, and the npm and Python packages installed in it.',
              'An image on its own: open its dependency tree (Rules or Review) and use **SBOM of what is inside**, CycloneDX or SPDX. An image not scanned yet is named in a note, never shown as empty.'
            ] }
          ]
        },
        {
          id: 'admin-modes', title: 'Registry modes: degraded and lockdown',
          summary: 'Slow or stop what comes in from outside during an ecosystem wide incident or an outage.',
          keywords: ['registry mode', 'degraded', 'lockdown', 'outage', 'offline', 'upstream down', 'incident', 'stale', 'freeze'],
          blocks: [
            { t: 'diagram', id: 'admin-modes' },
            { t: 'p', text: 'Change the mode on the **Dashboard**, under **Registry mode**. A reason is required, every change is audited and admins are emailed. Approvers can raise the mode. Only admins can lower it.' },
            { t: 'h', text: 'When the upstream registry is down' },
            { t: 'list', items: [
              'npm and PyPI metadata is served from cache for up to **Seconds we will serve stale metadata if upstream is down** (default 7 days).',
              'Files already cached are always served.',
              'Image tags confirmed within that window keep working. Pulls by digest of kept images never need Docker Hub.',
              'In lockdown, or with **Upstream registry enabled** off, kept copies are served at any age.'
            ] },
            { t: 'tip', text: 'Before a planned outage, cache what matters: allow rules with exact versions or tags, then **Cache now** on **Rules**.' }
          ]
        },
        {
          id: 'admin-scenarios', title: 'Scenarios: what happens, and what you do',
          summary: 'Real incidents walked through step by step.',
          keywords: ['scenario', 'playbook', 'runbook', 'incident', 'malicious release', 'typosquat', 'outage', 'critical cve', 'dependency confusion', 'leaked token'],
          blocks: [
            { t: 'h', text: '1. A popular npm package publishes a malicious version' },
            { t: 'list', items: [
              '**Automatic:** in whitelist mode with pinned ranges, the new version is not covered by any rule and never installs. With cooling off on, it is hidden for the waiting period. With malware scanning, a MALICIOUS verdict rejects it and emails admins. If the attacker replaces a version you already hold, an integrity alert holds it and the original bytes keep being served.',
              '**You:** kill the bad versions with a reason that names a safe version. Use **who pulled it** and **Consumers** to find affected builds. Raise the registry mode to degraded if the whole ecosystem is under attack.'
            ] },
            { t: 'h', text: '2. A developer mistypes a package name' },
            { t: 'list', items: [
              '**Automatic:** in whitelist mode the unknown name is refused as not on the whitelist and a request opens. In blacklist mode the lookalike check warns or blocks.',
              '**You:** block the request with a reason naming the real package. Consider **Typosquat checks: block**.'
            ] },
            { t: 'h', text: '3. Docker Hub is down' },
            { t: 'list', items: [
              '**Automatic:** cached layers are served, and tags confirmed in the last 7 days keep working. Uncached layers fail with a 502.',
              '**You:** switch to lockdown, or turn off **Upstream registry enabled**, to serve kept images at any age until Docker Hub is back.'
            ] },
            { t: 'h', text: '4. A critical CVE is published for a version you allow' },
            { t: 'list', items: [
              '**Automatic:** the next scan records the finding, npm warns during installs, `npm audit` reports it, and downloads are logged. With safe version resolution on, installs move to the newest safe version in range and exact downloads are refused.',
              '**You:** check **Vulnerabilities** and **Consumers**. If teams need time, grant scoped waivers with an end date. For an actively exploited advisory, kill it by advisory id.'
            ] },
            { t: 'h', text: '5. Someone publishes your internal package name on public npm' },
            { t: 'list', items: [
              '**Automatic:** if the name is reserved, the public copy is never fetched. Otherwise the public package could be installed.',
              '**You:** reserve the scope or prefix now, keep **fall back** off on internal registries, and search **Consumers** for the public name.'
            ] },
            { t: 'h', text: '6. A token leaks in a public repository' },
            { t: 'list', items: [
              '**You:** revoke it on **Tokens**, then filter **Traffic** by its application and look for unfamiliar addresses. Consider the client allow list with **Let a valid token through from any network** off.'
            ] }
          ]
        }
      ]
    },
    // ================================================================================================ visibility
    {
      id: 'visibility', label: 'Watching the system',
      topics: [
        {
          id: 'admin-dashboard', title: 'The dashboard',
          summary: 'What each card means and where it leads.',
          keywords: ['dashboard', 'cards', 'metrics', 'bandwidth', 'vulnerable packages', 'malicious packages', 'risky packages', 'overview'],
          blocks: [
            { t: 'shot', id: 'admin-dashboard' },
            { t: 'table', head: ['Card', 'Counts'], rows: [
              ['Vulnerable packages', 'Packages with findings, how many versions are critical or high, and how many are on CISA KEV.'],
              ['Malicious packages', 'Refused installs in 24 hours, malware flags, lookalikes and kills.'],
              ['`License violations`', 'Blocked packages and those waiting for a license review.'],
              ['Risky packages in use', 'Vulnerable versions pulled in the last 30 days, sorted by risk.'],
              ['Integrity alerts', 'Open alerts and the packages affected.'],
              ['Waivers ending soon', 'Waivers ending in 7 days, and those that just ended.'],
              ['Bandwidth', 'Bytes pulled by clients, fetched from upstream and pushed by publishing, over 24 hours with daily averages.']
            ] },
            { t: 'p', text: 'Click a card to list what is behind it. The numbers are kept for **Minutes to keep the dashboard numbers** (default 30). **Work them out again** recounts now.' }
          ]
        },
        {
          id: 'admin-traffic-audit', title: 'Traffic, resolutions and the audit trail',
          summary: 'Every registry request, every version left out, and every change made in the portal.',
          keywords: ['traffic', 'logs', 'access log', 'audit trail', 'resolutions', 'export logs', 'siem', 'who did what', 'retention'],
          blocks: [
            { t: 'shot', id: 'admin-traffic' },
            { t: 'list', items: [
              '**Traffic** lists every registry request. Filter by package, application, environment, and blocked, served, errors or would have blocked. Click **why** on a row for the full reason. Export CSV or JSON.',
              '**Resolutions** shows, while safe resolution or cooling off is on, what npm and pip were offered, what was left out and why, and which version the client pulled.',
              '**Utilization** shows CPU, memory, disk and network for the host and for {{name}}.'
            ] },
            { t: 'shot', id: 'admin-audit' },
            { t: 'p', text: 'The **Audit trail** records sign ins, failed sign ins, settings, rules, users, tokens, kills, decisions and exports, with before and after values. Secrets appear as stars. Traffic is kept for **Days of traffic log to keep** (default 30) and the audit trail four times as long.' }
          ]
        },
        {
          id: 'admin-integrations', title: 'Integrations: webhooks, Splunk and syslog',
          summary: 'Send security events to your SIEM or chat tools.',
          keywords: ['integrations', 'webhook', 'splunk', 'hec', 'syslog', 'cef', 'siem', 'events', 'hmac', 'signature'],
          blocks: [
            { t: 'shot', id: 'admin-integrations' },
            { t: 'table', head: ['Kind', 'Notes'], rows: [
              ['Webhook', 'https only. With a secret of 16 or more characters, each request carries `x-forgerepo-signature: sha256=<HMAC of timestamp.body>` and `x-forgerepo-timestamp`.'],
              ['Splunk HEC', 'https only. The HEC token is the secret.'],
              ['Syslog', 'tls, tcp or udp, JSON or CEF. Port 6514 by default for tls.']
            ] },
            { t: 'p', text: 'Pick events such as `package.blocked`, `package.quarantined`, `malware.detected`, `vulnerability.discovered`, `artifact.integrity_changed`, `waiver.created` and `policy.violation`, or every event. Deliveries retry with backoff for up to 10 attempts. Use **test** to send one now and **deliveries** to see what happened.' },
            { t: 'note', text: 'Addresses on the server itself and cloud metadata addresses are refused, and redirects are not followed.' }
          ]
        }
      ]
    },
    // ================================================================================================ operations
    {
      id: 'ops', label: 'Operations',
      topics: [
        {
          id: 'admin-cache-storage', title: 'Cache, storage and retention',
          summary: 'Where files live, how long things are kept, and how to clean up.',
          keywords: ['cache', 'storage', 's3', 'azure blob', 'disk', 'purge', 'retention', 'drift', 'recache', 'packument ttl', 'packages page', 'cached images', 'find image'],
          blocks: [
            { t: 'table', head: ['Setting (Cache tab)', 'Default', 'Meaning'], rows: [
              ['Keep tarballs on disk', 'on', 'Off serves files once without keeping them. Scan before serving keeps them anyway, since it can only hold a file it kept.'],
              ['Seconds before metadata is refetched', '300', 'How fresh npm and PyPI metadata is.'],
              ['Seconds we will serve stale metadata if upstream is down', '604800', '7 days of outage protection.'],
              ['Days of traffic log to keep', '30', 'The audit trail is kept 4 times as long.'],
              ['Days to remember who consumed what', '365', '0 keeps it forever.']
            ] },
            { t: 'p', text: 'The **Storage** tab keeps files on local disk, S3 (or anything that speaks S3), or Azure Blob. **Save and test the bucket** changes nothing if the test fails. **Local copies to keep, in MB** keeps a fast local cache in front of the bucket.' },
            { t: 'p', text: 'The **Packages** page lists npm packages by default. Pick PyPI or images under **Type** to search those too. For an image it shows how many tags are held completely, how many times it was pulled, and a link to its files on **Artifacts**.' },
            { t: 'h', text: 'Cleaning up (Packages page)' },
            { t: 'list', items: [
              '**Purge cache** or **Forget** ticked packages. They download again when next asked.',
              '**Check for drift** reports files missing from disk and changes nothing.',
              '**Recache missing** restores missing files. **Purge blocked** removes files the rules now block.',
              '**Empty the entire cache** is admin only.'
            ] }
          ]
        },
        {
          id: 'admin-backup', title: 'Backups, import and export',
          summary: 'Move rules and configuration between servers, and back up the database.',
          keywords: ['backup', 'restore', 'export', 'import', 'rules csv', 'rules json', 'config export', 'migrate', 'mariadb dump'],
          blocks: [
            { t: 'shot', id: 'admin-transfer' },
            { t: 'list', items: [
              '**Rules as JSON** or **Rules as CSV**: every role that can read rules.',
              '**Whole config**: settings, both network allow lists and rules. It never includes users, tokens, keys or secrets.',
              '**Import rules**: pick or paste a file, choose `merge` or `replace` (replace only wipes the types in the file), and use **Try it first** before **Import**.',
              '**Import a whole config**: choose whether settings and the allow list come across too. Settings go through the same checks as the Settings page.'
            ] },
            { t: 'code', file: 'rules.csv', text: 'pattern,kind,version_range,note,priority,enabled\nexpress,allow,^4.21.0,web framework,0,1\nevent-stream,deny,,compromised in 2018,1000,1\n@acme/*,allow,,our own packages,0,1' },
            { t: 'h', text: 'Database backups' },
            { t: 'code', lang: 'bash', file: 'on the server', text: 'docker exec npm-repo mariadb-dump --socket=/run/mysqld/mysqld.sock --single-transaction --routines --triggers npmrepo > backup-$(date +%F).sql' },
            { t: 'warn', text: 'A config export is not a backup of users, tokens or the traffic history. Back up the database and the data directory.' }
          ]
        },
        {
          id: 'admin-upgrade-ha', title: 'Upgrades, health and high availability',
          summary: 'Upgrade safely, roll back, monitor health, and run more than one node.',
          keywords: ['upgrade', 'setup.sh', 'rollback', 'health', 'healthcheck', 'high availability', 'ha', 'cluster', 'shared database', 'reverse proxy', 'nginx', 'docker compose'],
          blocks: [
            { t: 'code', lang: 'bash', file: 'on the server', text: './setup.sh --upgrade          # pull, keep the old image as npm-repo:previous, rebuild, restart, wait for health\ncurl -s {{origin}}/_health    # {"ok":true}, or a 503 if the database is unreachable\n\n# roll back, if the database was not upgraded to a newer MariaDB\ndocker tag npm-repo:previous npm-repo:latest && docker compose up -d' },
            { t: 'list', items: [
              '`--upgrade` refuses to run over local edits and never touches `.env` or the data directory. Database changes run automatically at start.',
              'Plain `docker compose up -d` does not rebuild. Use `--build` or the upgrade script.',
              'Hard refresh the portal after an upgrade. The page is cached for five minutes.'
            ] },
            { t: 'h', text: 'More than one node' },
            { t: 'list', items: [
              'Point every node at one MariaDB with `DB_HOST`. Rules, users, sessions, tokens, settings, allow lists and findings are shared.',
              'Cached files are not shared unless you use S3 or Azure storage. Otherwise sync the cache directory and run **Check for drift** after a failover.',
              'Settings reach other nodes within 30 seconds, rules within 5. Background jobs run on every node, so active and passive is recommended.'
            ] },
            { t: 'h', text: 'Reverse proxy' },
            { t: 'p', text: 'Put nginx or another proxy with TLS in front, using the example in `nginx/npm-repo.conf.example`. The proxy must set `X-Forwarded-For` to the client address, and the container port should only listen on 127.0.0.1.' }
          ]
        },
        {
          id: 'admin-settings-reference', title: 'Settings reference',
          summary: 'Every policy setting in one place, with its default.',
          keywords: ['settings', 'reference', 'defaults', 'configuration', 'policy settings', 'all settings'],
          blocks: [
            { t: 'table', head: ['Policy tab setting', 'Default', 'Topic'], rows: [
              ['Mode', 'whitelist', '[Whitelist, blacklist and audit mode](#docs/admin-policy-modes)'],
              ['Audit only (learning mode)', 'off', '[Whitelist, blacklist and audit mode](#docs/admin-policy-modes)'],
              ['Quarantine', 'permissive', '[Quarantine and integrity alerts](#docs/admin-quarantine-integrity)'],
              ['Safe version resolution / Leave out advisories from', 'off / HIGH', '[Vulnerabilities](#docs/admin-safe-resolution)'],
              ['Cooling off, in hours / Never cooled off / A version with no publish time', '0 / empty / allow', '[Cooling off](#docs/admin-cooling-off)'],
              ['When provenance is INVALID', 'warn', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['When provenance goes backward', 'hold', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['When a release starts running code at install', 'warn', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['When an npm listing disagrees with its tarball', 'hold', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['When a release looks like a takeover', 'warn', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['Longest waiver, in days', '90', '[Deciding waivers](#docs/admin-waivers)'],
              ['Typosquat checks / Also protect / Never flag', 'warn / empty / empty', '[Licenses, lookalikes and provenance](#docs/admin-licenses-provenance)'],
              ['Open a request when an install is blocked', 'on', '[Deciding requests](#docs/admin-requests)'],
              ['Approving a request can approve its clean dependencies too', 'off', '[Deciding requests](#docs/admin-requests)'],
              ['Enforce lifecycle stages', 'off', '[Applications and environments](#docs/admin-scope)'],
              ['Tell blocked developers where the portal is', 'on', 'Adds "Ask for it at {{portal}}" to refusals.']
            ] },
            { t: 'note', text: '**Save settings** saves every tab at once. Registry rows, reserved names, applications and branding save on their own as soon as you change them.' }
          ]
        }
      ]
    }
  ]
};

export { ADMIN };
