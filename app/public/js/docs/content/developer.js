// ForgeRepo portal: the developer guide.
// Author: Tim Rice
//
// every command here was run against a test box and every screenshot taken from it, see Documentation_Instructions.md
// before changing a claim. addresses are {{placeholders}} so the reader sees their own

import { register } from '../diagrams.js';

register('dev-flow', {
  w: 760, h: 290, title: 'What happens when you install a package',
  nodes: [
    { id: 'you', x: 10, y: 100, w: 140, h: 70, text: 'Your tool\nnpm, pip, docker', kind: 'client' },
    { id: 'us', x: 195, y: 100, w: 170, h: 70, text: '{{name}}\n{{host}}', kind: 'registry' },
    { id: 'rules', x: 410, y: 100, w: 140, h: 70, text: 'Allowed by the rules?', kind: 'decision' },
    { id: 'no', x: 410, y: 225, w: 140, h: 55, text: '403 and the reason', kind: 'bad' },
    { id: 'public', x: 595, y: 10, w: 155, h: 70, text: 'Fetched from npmjs, PyPI or Docker Hub, then checked', kind: 'outside' },
    { id: 'ok', x: 595, y: 190, w: 155, h: 60, text: 'Served to you', kind: 'good' }
  ],
  edges: [
    { from: 'you', to: 'us', label: 'token' },
    { from: 'us', to: 'rules' },
    { from: 'rules', to: 'no', label: 'no', kind: 'bad' },
    { from: 'rules', to: 'public', label: 'yes' },
    { from: 'public', to: 'ok', kind: 'good' }
  ]
});

var DEVELOPER = {
  id: 'developer',
  title: 'Developer Guide',
  needs: ['requests:read:own'],
  intro: 'How to install packages and container images through {{name}}, set up your tools and pipelines, and what to do when something is blocked.',
  groups: [
    // ------------------------------------------------------------------------------------------------ start here
    {
      id: 'start', label: 'Start here',
      topics: [
        {
          id: 'what-is-it', title: 'What {{name}} does for you',
          summary: 'One address for every package and image your code uses, checked before it reaches your laptop or your pipeline.',
          keywords: ['overview', 'introduction', 'about', 'registry', 'proxy', 'mirror', 'why'],
          blocks: [
            { t: 'p', text: '{{name}} sits between your tools and the public registries. When you run `npm install`, `pip install` or `docker pull`, your tool asks {{name}} at **{{host}}** instead of the internet. {{name}} checks the package against your company rules, fetches it if it is allowed, and hands it back.' },
            { t: 'diagram', id: 'dev-flow', caption: 'Every install goes through the same checks, from a laptop or from a pipeline.' },
            { t: 'p', text: 'This protects you from packages that are malicious, typosquatted, known to be vulnerable, or simply not approved yet. It also means that when a bad version is found, your security team can see who has it and stop it everywhere at once.' },
            { t: 'h', text: 'What you need to do' },
            { t: 'steps', items: [
              'Sign in to the portal at **{{portal}}**. See [Signing in](#docs/sign-in).',
              'Make a token. See [Make a token](#docs/tokens).',
              'Point your tools at {{host}}: [npm](#docs/npm-setup), [pip](#docs/pip-setup) or [docker](#docs/docker-login).',
              'Install as usual. If something is blocked, the error says why. See [When something is blocked](#docs/blocked).'
            ] },
            { t: 'tip', text: 'Press **/** anywhere on this page to search. Try "yarn token" or "pull an image".' }
          ]
        },
        {
          id: 'sign-in', title: 'Signing in and finding your way around',
          summary: 'Sign in, see what your role can do, and change your password.',
          keywords: ['login', 'log in', 'password', 'account', 'role', 'navigation', 'menu', 'sso'],
          blocks: [
            { t: 'p', text: 'Open **{{portal}}** in your browser.' },
            { t: 'shot', id: 'sign-in', caption: 'The sign in page.' },
            { t: 'p', text: 'Your account has a role. The menu on the left only shows what your role can use, so two people may see different menus.', },
            { t: 'shot', id: 'portal-tour-developer', caption: 'The portal after signing in as a developer.' },
            { t: 'table', head: ['Role', 'What it can do'], rows: [
              ['viewer', 'Read the rules, packages and your own requests.'],
              ['developer', 'Everything a viewer can, plus make tokens, ask for packages, check packages and walk dependency trees.'],
              ['publisher', 'Everything a developer can, plus publish packages and push images under the names your company reserved.'],
              ['approver', 'Everything a publisher can, plus decide on requests and waivers and change rules.'],
              ['admin', 'Everything, including settings, users and traffic.']
            ] },
            { t: 'h', text: 'Change your password' },
            { t: 'p', text: 'Click your name at the top right to open **Your account**.' },
            { t: 'shot', id: 'account-password' },
            { t: 'note', text: 'If your company signs in with single sign-on, your password is managed there and this form may not apply to you.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ tokens
    {
      id: 'tokens-group', label: 'Access tokens',
      topics: [
        {
          id: 'tokens', title: 'Make a token',
          summary: 'A token lets npm, pip, docker and your pipelines prove who they are.',
          keywords: ['token', 'access token', 'api key', 'credentials', 'password', 'authToken', 'secret', 'create token'],
          needs: ['tokens:create:own'],
          blocks: [
            { t: 'p', text: 'Your tools do not use your portal password. They use a token instead. A token is a long random string that stands for you. You can have many, one for each laptop or pipeline, and you can revoke one without touching the others.' },
            { t: 'steps', items: [
              'Open **Tokens** in the menu.',
              'Under **New token**, type what the token is for, like `laptop` or `storefront-ci`.',
              'Pick how many days it lasts. Shorter is safer.',
              'Click **Make one**.'
            ] },
            { t: 'shot', id: 'token-new' },
            { t: 'p', text: 'The token is shown **once**. Copy it right away and keep it in a password manager or your pipeline secrets. The page also prints the exact setup commands for {{host}}.' },
            { t: 'shot', id: 'token-made', caption: 'A new token. The real token appears where this picture says <your token>.' },
            { t: 'warn', text: 'Treat a token like a password. Never commit it to git, paste it in chat, or put it in a Dockerfile. If one leaks, revoke it and make a new one.' },
            { t: 'h', text: 'Keep the token out of your files' },
            { t: 'p', text: 'Most tools can read the token from an environment variable. The examples in this guide use `NPM_TOKEN` for npm and `REPO_TOKEN` for pip and docker. Set it once in your shell profile:' },
            { t: 'code', lang: 'bash', file: '~/.bashrc or ~/.zshrc', text: 'export NPM_TOKEN="<your token>"\nexport REPO_TOKEN="$NPM_TOKEN"' },
            { t: 'see', ids: ['token-manage', 'npm-setup', 'pip-setup', 'docker-login'] }
          ]
        },
        {
          id: 'token-manage', title: 'Revoke a token, or check when it was used',
          summary: 'See your tokens, when they expire, and revoke the ones you no longer use.',
          keywords: ['revoke', 'delete token', 'expire', 'expired', 'leaked', 'lost', 'rotate'],
          needs: ['tokens:read:own'],
          blocks: [
            { t: 'p', text: 'The **Tokens** page lists every token you made, when it expires and when it was last used.' },
            { t: 'shot', id: 'token-list' },
            { t: 'steps', items: [
              'Find the token by its name.',
              'Click **revoke**. Anything still using it gets a 401 error right away.',
              'Make a new token and update the places that used the old one.'
            ] },
            { t: 'note', text: 'An admin can place a token in an application and an environment, like "storefront" and "production". Rules can be different for each one, so a token for production may be stricter than your laptop token.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ npm
    {
      id: 'npm', label: 'npm, pnpm and Yarn',
      topics: [
        {
          id: 'npm-setup', title: 'Set up npm', ecosystem: 'npm',
          summary: 'Point npm at {{host}} for one project or for your whole machine.',
          keywords: ['npm', 'npmrc', '.npmrc', 'registry', 'config', 'node', 'javascript', 'authToken', 'npm config set', 'comment', 'slashes', 'double slash', 'commented out', 'hash', 'semicolon'],
          blocks: [
            { t: 'p', text: 'npm reads its settings from a file called `.npmrc`. Put one in the root of your project so everyone who clones it uses {{host}}.' },
            { t: 'code', file: '.npmrc', text: 'registry={{npmRegistry}}\n{{npmAuthKey}}:_authToken=${NPM_TOKEN}' },
            { t: 'p', text: 'The first line sends every install to {{host}}. The second line gives npm your token, read from the `NPM_TOKEN` environment variable, so the file is safe to commit.' },
            { t: 'warn', text: 'A line starting with `//` is **not** a comment. In `.npmrc`, `//` starts a web address with the `https:` left off, and it says which registry the setting belongs to. So `{{npmAuthKey}}:_authToken=...` is the token for **{{host}}**, and `//google.com/:_authToken=...` would be a token for google.com. Delete a `//` line and your installs stop working.' },
            { t: 'p', text: 'Comments in `.npmrc` start with `#` or `;`:' },
            { t: 'code', file: '.npmrc', text: '# this is a comment, and so is the next line\n; both of these are ignored\n\n# the line below is a setting for one registry host, not a comment\n{{npmAuthKey}}:_authToken=${NPM_TOKEN}' },
            { t: 'term', id: 'npm-project-setup' },
            { t: 'p', text: '`npm whoami` printing your user name means the token works. `npm ping` answering PONG means npm can reach {{host}}.' },
            { t: 'h', text: 'For every project on your machine' },
            { t: 'code', lang: 'bash', text: 'npm config set registry {{npmRegistry}}\nnpm config set {{npmAuthKey}}:_authToken "$NPM_TOKEN"' },
            { t: 'p', text: 'This writes to `~/.npmrc` in your home folder. A project `.npmrc` still wins when both exist.' },
            { t: 'tip', text: 'Using a scope only for your company packages? You can send just the scope to {{host}} with `@acme:registry={{npmRegistry}}`. Sending everything is safer, because then every public package is checked too.' }
          ]
        },
        {
          id: 'npm-install', title: 'Install packages with npm', ecosystem: 'npm',
          summary: 'npm install and npm ci work the same way they always have.',
          keywords: ['npm install', 'npm i', 'npm ci', 'add package', 'dependencies', 'package-lock', 'lockfile'],
          blocks: [
            { t: 'p', text: 'Once npm points at {{host}}, install the way you always do.' },
            { t: 'term', id: 'npm-install' },
            { t: 'h', text: 'Lock files and npm ci' },
            { t: 'p', text: 'The `resolved` addresses in `package-lock.json` point at {{host}}. `npm ci` installs exactly what the lock file says, which is what a pipeline should run.' },
            { t: 'term', id: 'npm-ci' },
            { t: 'note', text: 'A lock file made before you switched may still say registry.npmjs.org. That is fine: npm 7 and later swap that address for the registry you set, so `npm ci` still installs through {{host}}.' },
            { t: 'h', text: 'npm audit' },
            { t: 'p', text: '`npm audit` asks {{host}} about the packages you installed. The answer comes from the advisories {{name}} knows about.' },
            { t: 'term', id: 'npm-audit' }
          ]
        },
        {
          id: 'pnpm', title: 'Set up pnpm', ecosystem: 'npm',
          summary: 'pnpm uses the same registry and token settings as npm.',
          keywords: ['pnpm', 'pnpm add', 'pnpm install', 'corepack'],
          blocks: [
            { t: 'term', id: 'pnpm-setup' },
            { t: 'note', text: 'Newer versions of pnpm do not read `${NPM_TOKEN}` from a project `.npmrc`. Use `pnpm config set` as shown, which writes the token to `~/.npmrc` in your home folder.' },
            { t: 'p', text: 'pnpm reads the same `.npmrc`, so the same trap applies: a `//` line is a setting, not a comment. See [Set up npm](#docs/npm-setup).' }
          ]
        },
        {
          id: 'yarn', title: 'Set up Yarn', ecosystem: 'npm',
          summary: 'Yarn 2 and later read .yarnrc.yml instead of .npmrc.',
          keywords: ['yarn', 'yarnrc', '.yarnrc.yml', 'berry', 'yarn add', 'npmRegistryServer', 'npmAuthToken'],
          blocks: [
            { t: 'code', file: '.yarnrc.yml', text: 'npmRegistryServer: "{{origin}}"\nnpmAuthToken: "${NPM_TOKEN}"\nnpmAlwaysAuth: true' },
            { t: 'term', id: 'yarn-setup' },
            { t: 'note', text: 'Keep `npmAlwaysAuth: true`. Without it Yarn sends no token for most packages and {{host}} answers 401.' },
            { t: 'p', text: 'Yarn 1 (classic) reads `.npmrc` like npm does, so use the [npm setup](#docs/npm-setup).' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ python
    {
      id: 'python', label: 'Python',
      topics: [
        {
          id: 'pip-setup', title: 'Set up pip', ecosystem: 'pypi',
          summary: 'Point pip at the {{name}} index.',
          keywords: ['pip', 'python', 'pypi', 'index-url', 'pip.conf', 'pip config', 'simple', '__token__'],
          blocks: [
            { t: 'p', text: 'The {{name}} Python index is at **{{pypiIndex}}**. pip sends the token as a password, with `__token__` as the user name.' },
            { t: 'term', id: 'pip-setup' },
            { t: 'p', text: 'That writes to your pip config file. You can also set it for one command, or with an environment variable in a pipeline:' },
            { t: 'code', lang: 'bash', text: 'pip install --index-url "https://__token__:${REPO_TOKEN}@{{host}}/pypi/simple/" requests\n\n# or\nexport PIP_INDEX_URL="https://__token__:${REPO_TOKEN}@{{host}}/pypi/simple/"' },
            { t: 'warn', text: 'Do not write the real token into `requirements.txt` or `pip.conf` inside your project. Keep it in the environment.' }
          ]
        },
        {
          id: 'pip-install', title: 'Install Python packages', ecosystem: 'pypi',
          summary: 'pip install and requirements files work as usual.',
          keywords: ['pip install', 'requirements.txt', 'venv', 'virtualenv', 'install python package'],
          blocks: [
            { t: 'term', id: 'pip-install' },
            { t: 'h', text: 'From requirements.txt' },
            { t: 'term', id: 'pip-requirements' }
          ]
        },
        {
          id: 'uv', title: 'Set up uv', ecosystem: 'pypi',
          summary: 'uv reads the index from UV_INDEX_URL.',
          keywords: ['uv', 'uv add', 'uv pip', 'UV_INDEX_URL', 'astral'],
          blocks: [
            { t: 'term', id: 'uv-add' },
            { t: 'p', text: 'To keep it in the project instead, add this to `pyproject.toml` and give uv the token with `UV_INDEX_COMPANY_USERNAME=__token__` and `UV_INDEX_COMPANY_PASSWORD`:' },
            { t: 'code', file: 'pyproject.toml', text: '[[tool.uv.index]]\nname = "company"\nurl = "{{pypiIndex}}"\ndefault = true' }
          ]
        },
        {
          id: 'poetry', title: 'Set up Poetry', ecosystem: 'pypi',
          summary: 'Add {{host}} as the primary source and give Poetry the token.',
          keywords: ['poetry', 'poetry add', 'poetry source', 'http-basic'],
          blocks: [
            { t: 'term', id: 'poetry-add' },
            { t: 'p', text: 'In a pipeline, skip `poetry config` and set these instead:' },
            { t: 'code', lang: 'bash', text: 'export POETRY_HTTP_BASIC_COMPANY_USERNAME=__token__\nexport POETRY_HTTP_BASIC_COMPANY_PASSWORD="$REPO_TOKEN"' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ images
    {
      id: 'images', label: 'Container images',
      topics: [
        {
          id: 'docker-login', title: 'Sign docker in to {{host}}', ecosystem: 'oci',
          summary: 'Use your token as the password for docker, podman or skopeo.',
          keywords: ['docker', 'docker login', 'podman', 'skopeo', 'container', 'image', 'oci', 'password-stdin', 'credentials'],
          blocks: [
            { t: 'p', text: 'docker signs in once per machine. Use your token as the password. The token decides who you are, so the user name is only a label, but your own user name makes the traffic log easier to read.' },
            { t: 'term', id: 'docker-login' },
            { t: 'tip', text: '`--password-stdin` keeps the token out of your shell history and out of the process list. Avoid `-p <token>`.' },
            { t: 'p', text: 'podman and skopeo take the same command: `podman login {{dockerHost}}`.' }
          ]
        },
        {
          id: 'docker-pull', title: 'Pull an image', ecosystem: 'oci',
          summary: 'Put {{host}}/ in front of the image name.',
          keywords: ['docker pull', 'pull image', 'image name', 'tag', 'digest', 'docker hub', 'library'],
          blocks: [
            { t: 'p', text: 'To pull an image through {{name}}, put `{{dockerHost}}/` in front of the name you would use with Docker Hub.' },
            { t: 'table', head: ['Instead of', 'Use'], rows: [
              ['`docker pull nginx:latest`', '`docker pull {{dockerHost}}/nginx:latest`'],
              ['`docker pull node:22-alpine`', '`docker pull {{dockerHost}}/node:22-alpine`'],
              ['`docker pull bitnami/redis:7.4`', '`docker pull {{dockerHost}}/bitnami/redis:7.4`']
            ] },
            { t: 'term', id: 'docker-pull' },
            { t: 'note', text: 'Pulling by digest works too, like `{{dockerHost}}/nginx@sha256:...`. A digest is only served when a tag the rules allow points at it, so a blocked tag cannot be pulled by its digest.' }
          ]
        },
        {
          id: 'dockerfile', title: 'Build with a base image from {{host}}', ecosystem: 'oci',
          summary: 'Change the FROM line and log in before you build.',
          keywords: ['Dockerfile', 'FROM', 'docker build', 'base image', 'buildkit', 'multi-stage'],
          blocks: [
            { t: 'term', id: 'docker-build' },
            { t: 'p', text: 'Change every `FROM` line, including the ones in multi-stage builds. The build uses the login you made with `docker login`.' },
            { t: 'code', file: 'Dockerfile', text: 'FROM {{dockerHost}}/node:22-alpine AS build\nWORKDIR /app\nCOPY . .\nRUN npm ci && npm run build\n\nFROM {{dockerHost}}/nginx:stable-alpine\nCOPY --from=build /app/dist /usr/share/nginx/html' },
            { t: 'warn', text: 'A `RUN npm ci` inside the build does not see your `NPM_TOKEN`. Pass it as a build secret, never as a build argument, because build arguments are saved in the image. See [npm inside a docker build](#docs/docker-build-secrets).' }
          ]
        },
        {
          id: 'docker-build-secrets', title: 'npm or pip inside a docker build', ecosystem: 'oci',
          summary: 'Give the build your token without saving it in the image.',
          keywords: ['build secret', 'secret mount', 'docker build npm', 'build-arg', 'buildkit secret', 'npmrc docker'],
          blocks: [
            { t: 'code', file: 'Dockerfile', text: '# syntax=docker/dockerfile:1\nFROM {{dockerHost}}/node:22-alpine\nWORKDIR /app\nCOPY package.json package-lock.json .npmrc ./\nRUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci\nCOPY . .' },
            { t: 'code', lang: 'bash', text: 'docker build --secret id=npm_token,env=NPM_TOKEN -t storefront .' },
            { t: 'p', text: 'The `.npmrc` from [Set up npm](#docs/npm-setup) reads `${NPM_TOKEN}`, and the secret mount sets it only while that one `RUN` step runs. For pip, mount the secret the same way and set `PIP_INDEX_URL` in the `RUN` line.' }
          ]
        },
        {
          id: 'compose', title: 'Docker Compose', ecosystem: 'oci',
          summary: 'Use the {{host}} names in compose.yaml.',
          keywords: ['compose', 'docker compose', 'docker-compose', 'compose.yaml', 'docker-compose.yml'],
          blocks: [
            { t: 'term', id: 'docker-compose' },
            { t: 'p', text: 'Compose uses the same `docker login`, so there is nothing else to set up.' }
          ]
        },
        {
          id: 'kubernetes', title: 'Kubernetes and containerd', ecosystem: 'oci',
          summary: 'Give the cluster a pull secret made from a token.',
          keywords: ['kubernetes', 'k8s', 'imagePullSecrets', 'pull secret', 'containerd', 'k3s', 'registries.yaml', 'helm'],
          blocks: [
            { t: 'p', text: 'Use a token made for the cluster, not your personal one. Ask an admin to place it in the right application and environment.' },
            { t: 'code', lang: 'bash', text: 'kubectl create secret docker-registry repo-pull \\\n  --docker-server={{dockerHost}} \\\n  --docker-username=storefront-prod \\\n  --docker-password="$REPO_TOKEN"' },
            { t: 'code', file: 'deployment.yaml', text: 'spec:\n  template:\n    spec:\n      imagePullSecrets:\n        - name: repo-pull\n      containers:\n        - name: web\n          image: {{dockerHost}}/nginx:stable-alpine' },
            { t: 'h', text: 'k3s and plain containerd' },
            { t: 'code', file: '/etc/rancher/k3s/registries.yaml', text: 'configs:\n  "{{dockerHost}}":\n    auth:\n      username: storefront-prod\n      password: <your token>' }
          ]
        },
        {
          id: 'image-scanning', title: 'Image scanning and "try again in a minute"', ecosystem: 'oci',
          summary: 'Why a new image can make docker wait, and why a vulnerable one can be refused.',
          keywords: ['scan', 'scanning', 'toomanyrequests', '429', 'try again', 'vulnerable image', 'safe resolution', 'cve'],
          blocks: [
            { t: 'p', text: '{{name}} looks inside every image it serves and lists the packages in its layers. Your admin can turn on two extra checks:' },
            { t: 'list', items: [
              '**Scan before serve.** The first pull of an image nobody has pulled before waits for the scan. docker prints `toomanyrequests: it is being scanned for vulnerabilities before it is served, try again in a minute`. Wait a minute and pull again.',
              '**Safe resolution.** An image with serious advisories that an upgrade fixes is refused. The error names the advisories. Pick a newer tag, or ask for a [waiver](#docs/waivers).'
            ] },
            { t: 'p', text: 'To see what is inside an image before you use it, walk its tree. See [Check before you install](#docs/check).' },
            { t: 'shot', id: 'dependency-tree-image', caption: 'The tree of nginx:stable-alpine: one image for each platform, and the layers inside.' }
          ]
        },
        {
          id: 'image-push', title: 'Push an image', ecosystem: 'oci',
          summary: 'Push your own images under the names your admin reserved.',
          keywords: ['docker push', 'push image', 'publish image', 'upload image', 'reserved', 'namespace', 'tag', 'latest', 'tag invalid',
            'pushed tag never moves', 'denied', 'toomanyrequests', 'publisher', 'PUBLISH_TOKEN'],
          blocks: [
            { t: 'p', text: 'You can push when both of these are true:' },
            { t: 'list', items: [
              'Your role is **publisher**, approver or admin. A pipeline usually pushes with a token that belongs to a publisher account.',
              'The image name is reserved for your company, like everything under `acme/`. A reserved name is never pulled from a public registry, so nobody can publish a lookalike with the same name and have it pulled instead.'
            ] },
            { t: 'p', text: 'Build the image with **{{dockerHost}}** in front of its name, sign in with the publisher token, and push it:' },
            { t: 'term', id: 'docker-push' },
            { t: 'tip', text: 'In a pipeline, keep the token in a secret variable like `PUBLISH_TOKEN`. Never put it in the repository or the Dockerfile.' },
            { t: 'h', text: 'What happens next' },
            { t: 'list', items: [
              'Every layer is scanned for malware before anyone can pull the image. Until the scan is done, a pull says `toomanyrequests: ... is still being scanned for malware. Try again in a few minutes`.',
              'A layer the scanner flags is rejected, and a pull says what was found.',
              'When malware scanning is switched off, an admin releases the image on the **Quarantine** page before anyone can pull it.',
              'After that it pulls like any other image. In whitelist mode your admin adds an allow rule for your names.'
            ] },
            { t: 'h', text: 'A pushed tag never moves' },
            { t: 'p', text: 'Once a tag is pushed, it always means the same image, so the release you tested is the release that runs. Pushing different content under it is refused. Push the change under a new tag, like `1.4.1`. The one exception is `latest`, which moves to whatever you push under it last.' },
            { t: 'term', id: 'docker-push-tag-moved' },
            { t: 'h', text: 'If the push is refused' },
            { t: 'term', id: 'docker-push-refused' },
            { t: 'table', head: ['The error says', 'What to do'], rows: [
              ['cannot push here, it needs the publisher, approver or admin role', 'Push with a token owned by a publisher account, or ask an admin to change your role.'],
              ['is not a reserved name', 'Ask an admin to reserve the name or a namespace like `acme/*`.'],
              ['a pushed tag never moves', 'Push under a new tag.'],
              ['pushing needs a token', 'Run `docker login {{dockerHost}}` with your user name and a token as the password.'],
              ['nothing is deleted through the registry here', 'Pushed images are kept. Push a new tag instead of replacing an old one.']
            ] }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ nuget
    {
      id: 'nuget', label: '.NET and NuGet',
      topics: [
        {
          id: 'nuget-setup', title: 'Set up dotnet', ecosystem: 'nuget',
          summary: 'Point dotnet, nuget.exe and Visual Studio at the {{name}} NuGet feed.',
          keywords: ['nuget', 'dotnet', '.net', 'c#', 'nuget.config', 'packageSources', 'packageSourceCredentials', 'visual studio', 'csproj', 'index.json'],
          blocks: [
            { t: 'p', text: 'The {{name}} NuGet feed is at **{{origin}}/nuget/v3/index.json**. Put a `nuget.config` next to your solution with the feed and your token:' },
            { t: 'term', id: 'nuget-setup' },
            { t: 'list', items: [
              '`<clear />` removes nuget.org, so every package comes through {{host}} and its checks.',
              '`%REPO_TOKEN%` is read from the environment, so the token itself never goes into the repository.',
              'Visual Studio reads the same `nuget.config`. Search is not offered by the feed yet, so the **Browse** tab finds nothing here. Add packages by name.'
            ] }
          ]
        },
        {
          id: 'nuget-add', title: 'Add and restore packages', ecosystem: 'nuget',
          summary: 'Add a package and restore a project, the same as with nuget.org.',
          keywords: ['dotnet add package', 'dotnet restore', 'PackageReference', 'nuget install', 'restore', 'NU1101', 'NU1102'],
          blocks: [
            { t: 'p', text: 'Add a package the usual way. You get the newest version the rules allow. It can be older than the newest one on nuget.org.' },
            { t: 'term', id: 'nuget-add' },
            { t: 'p', text: 'Restore works the same way on any machine and in a pipeline:' },
            { t: 'term', id: 'nuget-restore' }
          ]
        },
        {
          id: 'nuget-ci', title: 'NuGet in a pipeline', ecosystem: 'nuget',
          summary: 'Add the feed with one command and restore.',
          keywords: ['dotnet nuget add source', 'pipeline', 'ci', 'github actions', 'azure pipelines', 'store-password-in-clear-text'],
          blocks: [
            { t: 'p', text: 'In a pipeline, add the feed from the command line with the token from a secret variable:' },
            { t: 'term', id: 'nuget-add-source' },
            { t: 'note', text: 'The password is only stored in the build machine\'s own NuGet settings. Use a token made for the pipeline, not your personal one.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ maven
    {
      id: 'maven', label: 'Java, Maven and Gradle',
      topics: [
        {
          id: 'maven-setup', title: 'Set up Maven', ecosystem: 'maven',
          summary: 'Point mvn at the {{name}} Maven repository with a mirror in settings.xml.',
          keywords: ['maven', 'mvn', 'java', 'settings.xml', 'mirror', 'mirrorOf', 'pom.xml', 'repository', 'jar', 'servers'],
          blocks: [
            { t: 'p', text: 'The {{name}} Maven repository is at **{{origin}}/maven/**. Add it as a mirror in `~/.m2/settings.xml`, with your token as the password:' },
            { t: 'term', id: 'maven-setup' },
            { t: 'list', items: [
              '`mirrorOf *` sends every download through {{host}}, Maven Central and plugins included, so nothing skips the checks.',
              'The `server` id has to match the `mirror` id. That is how Maven knows which password to send.',
              '`${env.REPO_TOKEN}` is read from the environment, so the token never goes into the file.'
            ] },
            { t: 'p', text: 'Then build as usual:' },
            { t: 'term', id: 'maven-build' }
          ]
        },
        {
          id: 'gradle-setup', title: 'Set up Gradle', ecosystem: 'maven',
          summary: 'Use the {{name}} repository in build.gradle.',
          keywords: ['gradle', 'build.gradle', 'kotlin', 'repositories', 'mavenCentral', 'credentials', 'settings.gradle'],
          blocks: [
            { t: 'p', text: 'Replace `mavenCentral()` with the {{name}} repository, and read the token from the environment:' },
            { t: 'code', file: 'build.gradle', text: 'repositories {\n    maven {\n        url "{{origin}}/maven/"\n        credentials {\n            username = "{{user}}"\n            password = System.getenv("REPO_TOKEN")\n        }\n    }\n}' },
            { t: 'p', text: 'Put the same block under `pluginManagement` in `settings.gradle` so plugins come through {{host}} too.' }
          ]
        },
        {
          id: 'maven-versions', title: 'Version ranges and releases', ecosystem: 'maven',
          summary: 'A range picks the newest version the rules allow. Snapshots are not served.',
          keywords: ['version range', '[2.17,2.18)', 'LATEST', 'RELEASE', 'snapshot', 'SNAPSHOT', 'maven-metadata.xml'],
          blocks: [
            { t: 'p', text: 'A range like `[2.17,2.18)` picks the newest version the rules allow. That can be older than the newest one on Maven Central.' },
            { t: 'p', text: 'Only releases are served. A `-SNAPSHOT` version is a build in progress, so publish your own snapshots somewhere else.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ ruby
    {
      id: 'ruby', label: 'Ruby, gem and Bundler',
      topics: [
        {
          id: 'bundler-setup', title: 'Set up Bundler', ecosystem: 'rubygems',
          summary: 'Send every gem through {{name}} with a Bundler mirror, and keep your Gemfile as it is.',
          keywords: ['bundler', 'bundle install', 'Gemfile', 'gem', 'ruby', 'rails', 'mirror', 'bundle config', 'rubygems.org'],
          blocks: [
            { t: 'p', text: 'The {{name}} gem source is at **{{origin}}/rubygems/**. Tell Bundler to use it in place of rubygems.org, with your token as the password:' },
            { t: 'term', id: 'bundler-setup' },
            { t: 'list', items: [
              'The Gemfile keeps `source "https://rubygems.org"`. Bundler sends every request to the mirror instead.',
              'The second command stores your token for the mirror. In a pipeline, run the same two commands with the token from a secret variable.'
            ] },
            { t: 'p', text: 'Then install as usual:' },
            { t: 'term', id: 'bundle-install' }
          ]
        },
        {
          id: 'gem-setup', title: 'Set up gem install', ecosystem: 'rubygems',
          summary: 'Make {{host}} the only gem source for gem install.',
          keywords: ['gem install', 'gem sources', 'gemrc', '.gemrc', 'rubygems'],
          blocks: [
            { t: 'p', text: 'Add {{name}} as a source, then remove rubygems.org, so every gem comes through {{host}}:' },
            { t: 'code', lang: 'bash', text: 'gem sources --add "https://{{user}}:${REPO_TOKEN}@{{host}}/rubygems/"\ngem sources --remove https://rubygems.org/' },
            { t: 'warn', text: 'gem saves the source address, token included, in `~/.gemrc`. Use a token made for that machine, and never commit the file.' }
          ]
        },
        {
          id: 'gem-missing', title: 'When bundler cannot find a gem', ecosystem: 'rubygems',
          summary: 'A gem nobody approved yet looks like it does not exist.',
          keywords: ['Could not find gem', 'Unavailable For Legal Reasons', '451', 'not approved', 'bundle install fails'],
          blocks: [
            { t: 'p', text: 'Bundler reads the version list of every gem it might need, old versions included. A gem nobody approved yet shows no versions, so Bundler says it cannot find it:' },
            { t: 'term', id: 'gem-blocked' },
            { t: 'p', text: 'Ask for the gem on the [Requests page](#docs/requests). A download of a gem that is not approved is refused with a 451 status, and Bundler prints the reason.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ cocoapods
    {
      id: 'cocoapods', label: 'iOS and CocoaPods',
      topics: [
        {
          id: 'pod-setup', title: 'Set up CocoaPods', ecosystem: 'cocoapods',
          summary: 'Point your Podfile at the {{name}} CocoaPods CDN, and give pod your token in ~/.netrc.',
          keywords: ['cocoapods', 'pod install', 'Podfile', 'ios', 'swift', 'xcode', 'netrc', 'source', 'cdn'],
          blocks: [
            { t: 'p', text: 'Put the {{name}} CDN at the top of your Podfile, in place of the default one:' },
            { t: 'term', id: 'pod-setup' },
            { t: 'list', items: [
              'pod reads the login for {{host}} from `~/.netrc`. Make the file readable only by you with `chmod 600 ~/.netrc`.',
              'With the source line in the Podfile, every pod comes through {{host}}, and so does its code. pod never goes to GitHub for it.'
            ] },
            { t: 'p', text: 'Then install as usual:' },
            { t: 'term', id: 'pod-install' }
          ]
        },
        {
          id: 'pod-missing', title: 'When pod cannot find a pod', ecosystem: 'cocoapods',
          summary: 'A pod nobody approved yet is not listed.',
          keywords: ['Unable to find a specification', 'pod not found', 'not approved', 'pod repo update'],
          blocks: [
            { t: 'p', text: 'A pod nobody approved yet is not listed, so pod says it cannot find it. Running `pod repo update` does not help:' },
            { t: 'term', id: 'pod-blocked' },
            { t: 'p', text: 'Ask for the pod on the [Requests page](#docs/requests).' },
            { t: 'note', text: 'Some pods can never come through {{name}}: ones whose code is a git branch or commit rather than a tag, or that need git submodules. The podspec says why when {{host}} refuses it.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ swift
    {
      id: 'swift', label: 'Swift packages',
      topics: [
        {
          id: 'swift-setup', title: 'Set up SwiftPM', ecosystem: 'swift',
          summary: 'Point SwiftPM at the {{name}} package registry and log in with your token.',
          keywords: ['swift', 'swiftpm', 'swift package', 'package-registry', 'Package.swift', 'xcode', 'spm', 'registry', 'login'],
          blocks: [
            { t: 'p', text: 'Tell SwiftPM to use {{name}} as its package registry, then log in with your user name and your token as the password:' },
            { t: 'term', id: 'swift-setup' },
            { t: 'list', items: [
              '`--global` sets it for every package on your machine. Leave it out to set it for one package only.',
              'The login is saved in `~/.netrc` on Linux and in the keychain on a Mac. It needs https.',
              'A package is named by its identity, `scope.name`. `apple.swift-log` is github.com/apple/swift-log.',
              'SwiftPM warns that a source archive is not signed. {{name}} does not sign archives. SwiftPM checks each one against the checksum {{host}} gives it.'
            ] },
            { t: 'p', text: 'Name dependencies by identity in Package.swift, and in a product use the identity as the package name:' },
            { t: 'term', id: 'swift-resolve' },
            { t: 'note', text: 'A dependency written as a GitHub url still goes to GitHub. Add `--replace-scm-with-registry` to `swift package resolve` or `swift build`, and SwiftPM asks {{host}} for it instead.' }
          ]
        },
        {
          id: 'swift-missing', title: 'When SwiftPM cannot get a package', ecosystem: 'swift',
          summary: 'A package nobody approved is refused, and swift prints why.',
          keywords: ['not approved', 'server error 403', 'swift package resolve', 'failed fetching', 'releases list'],
          blocks: [
            { t: 'p', text: 'A package nobody approved yet is refused, and SwiftPM prints the reason:' },
            { t: 'term', id: 'swift-blocked' },
            { t: 'p', text: 'Asking for it this way already opened a request. You can also ask on the [Requests page](#docs/requests).' },
            { t: 'note', text: 'Only tags that are versions, like 1.6.1 or v1.6.1, are releases. A branch or a commit can not come through {{name}}.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ composer
    {
      id: 'composer', label: 'PHP and Composer',
      topics: [
        {
          id: 'composer-setup', title: 'Set up Composer', ecosystem: 'composer',
          summary: 'Point Composer at the {{name}} repository in place of Packagist, and give it your token.',
          keywords: ['composer', 'php', 'packagist', 'composer.json', 'auth.json', 'http-basic', 'repositories', 'laravel', 'symfony'],
          blocks: [
            { t: 'p', text: 'Add {{name}} as a repository, turn Packagist off, and save your login once for your machine:' },
            { t: 'term', id: 'composer-setup' },
            { t: 'list', items: [
              'With Packagist off, every package comes through {{host}}, and so does its code. Composer never goes to GitHub for it.',
              '`--global` saves the login in your own `auth.json`, not in the project. Never commit a token in `auth.json`.',
              'The user name is yours, and the password is your token.'
            ] },
            { t: 'p', text: 'Then install as usual:' },
            { t: 'term', id: 'composer-install' },
            { t: 'note', text: 'A composer.lock made before you switched still points at GitHub. Run `composer update` once through {{host}}, and commit the new lock file.' }
          ]
        },
        {
          id: 'composer-missing', title: 'When Composer cannot find a package', ecosystem: 'composer',
          summary: 'A package nobody approved is not listed, so Composer says it could not be found.',
          keywords: ['could not be found', 'not approved', 'composer require', 'minimum-stability', 'dev-main'],
          blocks: [
            { t: 'p', text: 'A package nobody approved yet is not listed. Composer only says it could not be found, it does not show a reason:' },
            { t: 'term', id: 'composer-blocked' },
            { t: 'p', text: 'Asking for it this way already opened a request. You can also ask on the [Requests page](#docs/requests).' },
            { t: 'note', text: 'Branches, like dev-main or 2.x-dev, never come through {{name}}. Only releases are served.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ rpm
    {
      id: 'rpm', label: 'Linux packages (dnf and yum)',
      topics: [
        {
          id: 'rpm-setup', title: 'Set up dnf and yum', ecosystem: 'rpm',
          summary: 'Point dnf at a {{name}} mirror of your distro with a .repo file, and give it your token.',
          keywords: ['dnf', 'yum', 'rpm', 'repo file', 'yum.repos.d', 'almalinux', 'rocky', 'rhel', 'baseurl', 'mirror'],
          blocks: [
            { t: 'p', text: 'Your admin tells you the mirror address. Put it in a .repo file under /etc/yum.repos.d/, with your user name and your token:' },
            { t: 'term', id: 'rpm-setup' },
            { t: 'list', items: [
              'Keep `gpgcheck=1`. Every package is still checked against the distro\'s own key.',
              'Keep `repo_gpgcheck=1` too, unless your admin says the mirror hands out a filtered index. Then it has to be 0.',
              'Make the file readable only by root: `chmod 600`, since it holds your token.',
              'Turn off the distro\'s own repositories, so every package comes through {{host}}.'
            ] },
            { t: 'p', text: 'Then install as usual:' },
            { t: 'term', id: 'rpm-install' }
          ]
        },
        {
          id: 'rpm-missing', title: 'When dnf cannot get a package', ecosystem: 'rpm',
          summary: 'A package the rules refuse is either not listed or refused on download.',
          keywords: ['Status code: 403', 'No match for argument', 'Cannot download', 'all mirrors were already tried'],
          blocks: [
            { t: 'p', text: 'dnf only shows the status code of a refusal, not the reason:' },
            { t: 'term', id: 'rpm-blocked' },
            { t: 'p', text: 'The refusal already opened a request. Open the address dnf printed in a browser, or look on the [Requests page](#docs/requests), to see why.' },
            { t: 'note', text: 'On a mirror that hands out a filtered index, a refused package is not listed at all, so dnf says No match for argument.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ apt
    {
      id: 'apt', label: 'Linux packages (apt)',
      topics: [
        {
          id: 'apt-setup', title: 'Set up apt', ecosystem: 'apt',
          summary: 'Point apt at a {{name}} mirror of Debian or Ubuntu, and give it your token.',
          keywords: ['apt', 'apt-get', 'debian', 'ubuntu', 'sources.list', 'auth.conf', 'signed-by', 'deb', 'mirror'],
          blocks: [
            { t: 'p', text: 'Your admin tells you the mirror address. Put it in your sources in place of the distro\'s own, and your login in /etc/apt/auth.conf.d/:' },
            { t: 'term', id: 'apt-setup' },
            { t: 'list', items: [
              'apt still checks the distro\'s signature on the index, so nothing changes about trust.',
              'Make the auth file readable only by root: `chmod 600`, since it holds your token.',
              'Remove the distro\'s own sources, so every package comes through {{host}}.',
              'A bare Debian or Ubuntu image has no CA certificates, so apt can not reach an https mirror. Install ca-certificates in your base image, or point `Acquire::https::CAInfo` at your company CA.'
            ] },
            { t: 'p', text: 'Then install as usual:' },
            { t: 'term', id: 'apt-install' },
            { t: 'note', text: 'If your admin set the mirror to a filtered index, it is signed by {{name}} instead of the distro. Fetch the key from {{origin}}/apt/signing-key.asc into /etc/apt/keyrings/ and add `[signed-by=/etc/apt/keyrings/forgerepo.asc]` to the line.' }
          ]
        },
        {
          id: 'apt-missing', title: 'When apt cannot get a package', ecosystem: 'apt',
          summary: 'A package the rules refuse is refused on download, and apt prints why.',
          keywords: ['403', 'not approved', 'Failed to fetch', 'Unable to locate package', 'has no installation candidate'],
          blocks: [
            { t: 'p', text: 'A package the rules refuse fails to download, and apt prints the reason:' },
            { t: 'term', id: 'apt-blocked' },
            { t: 'p', text: 'The refusal already opened a request. You can also ask on the [Requests page](#docs/requests).' },
            { t: 'note', text: 'On a mirror with a filtered index, a refused package is not listed at all, so apt says Unable to locate package.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ pipelines
    {
      id: 'pipelines', label: 'CI pipelines',
      topics: [
        {
          id: 'ci-basics', title: 'Pipelines: the short version',
          summary: 'One token per pipeline, kept in the pipeline secrets, and the same commands as your laptop.',
          keywords: ['ci', 'cd', 'pipeline', 'build server', 'jenkins', 'automation', 'service account', 'secrets'],
          blocks: [
            { t: 'steps', items: [
              'Make a token just for the pipeline, named after it, like `storefront-ci`. Ask an admin to place it in the application and environment it builds for.',
              'Save it as a secret in your CI system, for example `REPO_TOKEN`.',
              'Use the same setup commands as on your laptop, reading the token from that secret.',
              'Use `npm ci`, `pip install -r requirements.txt` or pinned image tags, so builds install exactly what you tested.'
            ] },
            { t: 'tip', text: 'When a pipeline install is blocked, the error line in the build log says what and why. The package is often already waiting in [Requests](#docs/requests) for an approver.' }
          ]
        },
        {
          id: 'github-actions', title: 'GitHub Actions',
          summary: 'setup-node, pip and docker login in a GitHub workflow.',
          keywords: ['github', 'github actions', 'workflow', 'setup-node', 'NODE_AUTH_TOKEN', 'docker/login-action', 'actions'],
          blocks: [
            { t: 'code', file: '.github/workflows/build.yml', text: 'jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      # npm\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 22\n          registry-url: {{npmRegistry}}\n      - run: npm ci\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.REPO_TOKEN }}\n\n      # Python\n      - run: pip install -r requirements.txt\n        env:\n          PIP_INDEX_URL: https://__token__:${{ secrets.REPO_TOKEN }}@{{host}}/pypi/simple/\n\n      # images\n      - uses: docker/login-action@v3\n        with:\n          registry: {{dockerHost}}\n          username: storefront-ci\n          password: ${{ secrets.REPO_TOKEN }}\n      - run: docker build -t storefront .' },
            { t: 'note', text: '`setup-node` writes an `.npmrc` that reads `NODE_AUTH_TOKEN`, so you do not need your own for the pipeline.' }
          ]
        },
        {
          id: 'gitlab-ci', title: 'GitLab CI',
          summary: 'Job images, npm and pip in .gitlab-ci.yml.',
          keywords: ['gitlab', 'gitlab ci', '.gitlab-ci.yml', 'DOCKER_AUTH_CONFIG', 'runner'],
          blocks: [
            { t: 'code', file: '.gitlab-ci.yml', text: 'build:\n  image: {{dockerHost}}/node:22-alpine\n  script:\n    - npm config set registry {{npmRegistry}}\n    - npm config set "{{npmAuthKey}}:_authToken" "$REPO_TOKEN"\n    - npm ci\n\ntest-python:\n  image: {{dockerHost}}/python:3.12-slim\n  variables:\n    PIP_INDEX_URL: "https://__token__:${REPO_TOKEN}@{{host}}/pypi/simple/"\n  script:\n    - pip install -r requirements.txt' },
            { t: 'p', text: 'For the runner to pull the job image itself from {{host}}, add a CI/CD variable named `DOCKER_AUTH_CONFIG`:' },
            { t: 'code', lang: 'json', text: '{ "auths": { "{{dockerHost}}": { "auth": "<base64 of user:token>" } } }' },
            { t: 'p', text: 'Make the value with `printf "storefront-ci:%s" "$REPO_TOKEN" | base64`.' }
          ]
        },
        {
          id: 'other-ci', title: 'Jenkins, Azure Pipelines and others',
          summary: 'Any CI system works the same way: a secret and the setup commands.',
          keywords: ['jenkins', 'azure', 'azure devops', 'bitbucket', 'circleci', 'teamcity', 'buildkite'],
          blocks: [
            { t: 'code', lang: 'bash', file: 'any CI step', text: '# npm\nnpm config set registry {{npmRegistry}}\nnpm config set "{{npmAuthKey}}:_authToken" "$REPO_TOKEN"\nnpm ci\n\n# Python\nexport PIP_INDEX_URL="https://__token__:${REPO_TOKEN}@{{host}}/pypi/simple/"\npip install -r requirements.txt\n\n# images\necho "$REPO_TOKEN" | docker login {{dockerHost}} -u ci --password-stdin\ndocker pull {{dockerHost}}/node:22-alpine' },
            { t: 'warn', text: 'Make sure your CI system hides the secret in logs. Never run `set -x` or `env` in a step that has the token.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ publishing
    {
      id: 'publishing', label: 'Publishing',
      topics: [
        {
          id: 'publish-npm', title: 'Publish an npm package', ecosystem: 'npm',
          summary: 'Publish company packages under the names your admin reserved.',
          keywords: ['npm publish', 'publish', 'private package', 'scope', '@acme', 'reserved name', 'publishConfig'],
          blocks: [
            { t: 'p', text: 'You can publish when both of these are true:' },
            { t: 'list', items: [
              'Your role is **publisher**, approver or admin.',
              'The name is reserved for your company, like everything under `@acme/`. Reserving a name stops anyone from pulling a public package with the same name, which is how dependency confusion attacks work.'
            ] },
            { t: 'p', text: 'Add `publishConfig` so the package can never go to the public registry by mistake:' },
            { t: 'term', id: 'npm-publish' },
            { t: 'note', text: 'In whitelist mode your own packages still need an allow rule before anyone can install them. Ask an approver to add one for your scope, like `@acme/*`.' },
            { t: 'h', text: 'If your role cannot publish' },
            { t: 'term', id: 'npm-publish-refused' },
            { t: 'table', head: ['Error says', 'What to do'], rows: [
              ['cannot publish here, it needs the publisher, approver or admin role', 'Ask an admin to change your role, or publish from a pipeline token owned by a publisher account.'],
              ['is not a reserved name', 'Ask an admin to reserve the name or scope.'],
              ['is already published, and a published version never changes', 'Bump the version in `package.json` and publish again.']
            ] }
          ]
        },
        {
          id: 'publish-python', title: 'Publish a Python package', ecosystem: 'pypi',
          summary: 'Upload wheels and source archives with twine.',
          keywords: ['twine', 'twine upload', 'upload', 'wheel', 'sdist', 'publish python', 'pyproject'],
          blocks: [
            { t: 'p', text: 'The same rules apply as for npm: a publisher role and a reserved project name. Upload to **{{pypiUpload}}**.' },
            { t: 'term', id: 'twine-upload' },
            { t: 'code', file: '~/.pypirc', text: '[distutils]\nindex-servers = company\n\n[company]\nrepository = {{pypiUpload}}\nusername = __token__' },
            { t: 'p', text: 'With that file, run `twine upload -r company dist/*` and twine asks for the token, or reads it from `TWINE_PASSWORD`.' }
          ]
        },
        {
          id: 'publish-maven', title: 'Deploy to Maven', ecosystem: 'maven',
          summary: 'Deploy a release with mvn deploy.',
          keywords: ['mvn deploy', 'maven deploy', 'distributionManagement', 'settings.xml', 'publish jar', 'gradle publish'],
          blocks: [
            { t: 'p', text: 'The same rules apply as for npm: a publisher role and a reserved coordinate. Point the project at this repository, put your token in settings.xml as the password of that server, and deploy:' },
            { t: 'code', file: 'pom.xml', text: '<distributionManagement>\n  <repository><id>company</id><url>{{publicUrl}}/maven/</url></repository>\n</distributionManagement>' },
            { t: 'code', file: 'mvn deploy', text: 'mvn -B deploy' },
            { t: 'list', items: [
              'A deployed file never changes. Deploying the same bytes again is fine; different bytes under the same version are refused.',
              'Snapshots are not deployed here, only releases.',
              'The version list this repository serves is built from what was deployed, not from the maven-metadata.xml your build uploads.',
              'A new deploy is held until its malware scan is clean, or until an admin releases it. Then other builds resolve it.'
            ] }
          ]
        },
        {
          id: 'publish-gem', title: 'Publish a gem', ecosystem: 'rubygems',
          summary: 'Push a .gem with gem push.',
          keywords: ['gem push', 'publish gem', 'rubygems push', 'gem build', 'gemspec', 'api key', 'GEM_HOST_API_KEY'],
          blocks: [
            { t: 'p', text: 'The same rules apply as for npm: a publisher role and a reserved gem name. Build it, then push it with your token as the API key:' },
            { t: 'code', file: 'push a gem', text: 'gem build acme-logger.gemspec\nGEM_HOST_API_KEY=<your token> gem push acme-logger-1.0.0.gem --host {{publicUrl}}/rubygems' },
            { t: 'list', items: [
              'The host is the same source you install from.',
              'A pushed version never changes. `gem yank` is refused, so push a new version instead.',
              'A new push is held until its malware scan is clean, or until an admin releases it. Then `gem install` and `bundle install` see it.'
            ] }
          ]
        },
        {
          id: 'publish-nuget', title: 'Publish a NuGet package', ecosystem: 'nuget',
          summary: 'Push a .nupkg with dotnet nuget push.',
          keywords: ['dotnet nuget push', 'nuget push', 'publish nuget', 'nupkg', 'dotnet pack', 'api key', 'push package'],
          blocks: [
            { t: 'p', text: 'The same rules apply as for npm: a publisher role and a reserved package id. Pack the project, then push it with your token as the API key:' },
            { t: 'term', id: 'nuget-push' },
            { t: 'list', items: [
              'The feed address is the same one you restore from. dotnet finds where to push in it.',
              'A pushed version never changes. `dotnet nuget delete` is refused, so push a new version instead.',
              'A new push is held until its malware scan is clean, or until an admin releases it. Then `dotnet add package` sees it.'
            ] }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ requests
    {
      id: 'requests-group', label: 'Blocked packages and requests',
      topics: [
        {
          id: 'blocked', title: 'When something is blocked',
          summary: 'Read the reason, then ask for the package or pick a different version.',
          keywords: ['blocked', '403', 'forbidden', 'E403', 'denied', 'not approved', 'whitelist', 'error', 'no matching distribution', 'pull access denied'],
          blocks: [
            { t: 'p', text: 'A blocked install fails with a 403 error. The message says what was refused and why.' },
            { t: 'h', text: 'npm' },
            { t: 'term', id: 'npm-blocked' },
            { t: 'h', text: 'docker' },
            { t: 'term', id: 'docker-blocked' },
            { t: 'h', text: 'pip' },
            { t: 'p', text: 'pip hides the reason and only says "No matching distribution found". Ask {{host}} directly to see it:' },
            { t: 'term', id: 'pip-blocked' },
            { t: 'h', text: 'mvn' },
            { t: 'p', text: 'mvn prints the reason in the error line, after the status code:' },
            { t: 'term', id: 'maven-blocked' },
            { t: 'h', text: 'dotnet' },
            { t: 'p', text: 'dotnet prints the reason as a `warn` line, then fails with "There are no versions available for the package":' },
            { t: 'term', id: 'nuget-blocked' },
            { t: 'h', text: 'Common reasons' },
            { t: 'table', head: ['The reason says', 'What it means', 'What to do'], rows: [
              ['not on the whitelist', 'Nobody has approved this package yet.', '[Ask for it](#docs/requests). It may already be waiting.'],
              ['blocked by rule', 'Someone decided this package or version must not be used.', 'Pick another package or version. Ask an approver why if it is not clear.'],
              ['on the kill switch', 'The version was found to be malicious or compromised. The text after it says why.', 'Stop using it now. Move to a version that is not killed.'],
              ['advisory ... safe resolution leaves out', 'The version has known vulnerabilities at or above the level your company refuses.', 'Upgrade to a fixed version, or ask for a [waiver](#docs/waivers).'],
              ['held in quarantine', 'The file is being checked, for example by a malware scan, or failed a check.', 'Try again later, or use the version before it.'],
              ['new versions wait ... hours', 'The version is very new. New releases wait a while in case they turn out to be malicious. The message says when it will be served.', 'Use the previous version for now, or ask for a cooling off [waiver](#docs/waivers).'],
              ['a possible typosquat', 'The name looks like a popular package with a letter changed.', 'Check the spelling. You probably meant the package it names.']
            ] },
            { t: 'see', ids: ['requests', 'check'] }
          ]
        },
        {
          id: 'requests', title: 'Ask for a package or image',
          summary: 'Send a request to the approvers, and follow what happens to it.',
          keywords: ['request', 'ask for package', 'approval', 'approve', 'new package', 'pending', 'send it'],
          needs: ['requests:create'],
          blocks: [
            { t: 'steps', items: [
              'Open **Requests** in the menu.',
              'Pick the type: npm, PyPI or images.',
              'Type the name as you would install or pull it.',
              'Type the versions you need. For npm use a range like `^4.21.0`. For images use a tag like `7.4-alpine`. Leave it empty to ask for every version.',
              'Say why you need it. A good reason gets a faster answer.',
              'Click **Send it**.'
            ] },
            { t: 'shot', id: 'request-image' },
            { t: 'p', text: 'Your request is scanned for malware and checked for advisories straight away. That takes up to 10 minutes for a package and up to 30 minutes for a new image, so try again later. If your admin has switched on auto approve, a request that comes back clean is approved by itself.' },
            { t: 'p', text: 'Your requests are listed below the form, with what the check found. An install that was blocked may already have made a request for you, with the token that tried it.' },
            { t: 'shot', id: 'request-list' },
            { t: 'note', text: 'You only see your own requests. Approvers see everyone\'s.' }
          ]
        },
        {
          id: 'check', title: 'Check before you install',
          summary: 'See what the rules say about a version, and everything it pulls in.',
          keywords: ['check package', 'check it', 'dependency tree', 'walk the tree', 'transitive', 'dependencies', 'what will be blocked', 'preview'],
          needs: ['tools:resolve'],
          blocks: [
            { t: 'p', text: 'Open **Check a package**. Under **Single package**, type a name and version and click **Check it**.' },
            { t: 'shot', id: 'check-package' },
            { t: 'h', text: 'The dependency tree' },
            { t: 'p', text: 'A package can pull in dozens of others. **Walk the tree** shows every one of them and whether the rules would block it. Do this before you add a new package, so you can ask for everything it needs in one go.' },
            { t: 'shot', id: 'dependency-tree-npm', caption: 'axios and the 29 packages it pulls in.' },
            { t: 'p', text: 'For an image, pick **images** as the type and a tag as the version. The tree lists one image per platform and the layers inside each one.' },
            { t: 'see', ids: ['review-file', 'image-scanning'] }
          ]
        },
        {
          id: 'review-file', title: 'Review a whole lock file',
          summary: 'Upload a lock file, an SBOM or a software inventory and see what the rules make of every package, of every type.',
          keywords: ['review a file', 'upload lockfile', 'package-lock.json', 'yarn.lock', 'pnpm-lock', 'requirements', 'poetry.lock', 'uv.lock', 'sbom', 'cyclonedx', 'spdx', 'inventory', 'csv', 'purl', 'bom-ref', 'nuget', 'maven', 'gem', 'cocoapods', 'swift'],
          needs: ['rules:read'],
          blocks: [
            { t: 'p', text: 'On **Check a package**, scroll to **Review a file**. Pick your lock file and click **Review it**. The file is read in memory and is not kept.' },
            { t: 'shot', id: 'review-file' },
            { t: 'p', text: 'Each row says whether the version is allowed, blocked or needs a decision, and lists known advisories. Tick the rows that need a decision to ask for all of them at once.' },
            { t: 'p', text: 'Every package is judged by the rules of its own type. A NuGet package is judged by the NuGet rules, never by an npm rule with the same name. The type shows next to each name.' },
            { t: 'list', items: [
              '**SBOMs**: CycloneDX (JSON or XML) and SPDX. The package url says the type, like pkg:nuget/Serilog@2.12.0. When a tool leaves the purl out, the bom-ref is read instead.',
              '**Inventories**: a CSV or JSON export from another tool, one package per row. An **ecosystem** column (nuget, pypi, maven, gem, cocoapods, swift, npm) or a **purl** column says the type. Without one, every row is read as npm.',
              '**Repeats**: a package listed once per repository is read once.',
              '**Left out**: repositories, applications and types this registry has no rules for, like golang or cargo. The notes count them.'
            ] },
            { t: 'note', text: 'A type that is switched off on this box is left out, and the notes say so. An admin can switch it on under **Settings**.' }
          ]
        },
        {
          id: 'waivers', title: 'Ask for a waiver',
          summary: 'Keep using a version with a known advisory, for a limited time, with a reason on record.',
          keywords: ['waiver', 'exception', 'advisory', 'cve', 'vulnerability', 'accept risk', 'cooling off', 'license'],
          needs: ['requests:create'],
          blocks: [
            { t: 'p', text: 'Sometimes you cannot upgrade right away. A waiver lets a blocked version through for a set number of days. Someone who decides on waivers has to agree.' },
            { t: 'steps', items: [
              'Open **Waivers** in the menu.',
              'Pick what to waive: an advisory, a license hold, or the cooling off period.',
              'Type the package, the versions and how many days you need.',
              'Explain why it is safe for now, and add a ticket number if you have one.',
              'Click **Ask for it**.'
            ] },
            { t: 'shot', id: 'waiver-ask' },
            { t: 'note', text: 'You only see the waivers you asked for.' }
          ]
        },
        {
          id: 'vulnerabilities', title: 'See known vulnerabilities',
          summary: 'Which allowed versions have advisories, including packages inside images.',
          keywords: ['vulnerabilities', 'cve', 'advisory', 'osv', 'ghsa', 'severity', 'critical', 'image vulnerabilities'],
          needs: ['packages:read'],
          blocks: [
            { t: 'p', text: 'The **Vulnerabilities** page lists versions the rules allow today that have a known advisory. Filter by type, severity or name.' },
            { t: 'shot', id: 'vulnerabilities-images' },
            { t: 'p', text: 'Nothing on this page blocks an install by itself. It tells you what to upgrade.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ approvers
    {
      id: 'approving', label: 'For approvers',
      needs: ['requests:decide'],
      topics: [
        {
          id: 'decide-requests', title: 'Decide on requests',
          summary: 'Approve, block or clear what developers asked for.',
          keywords: ['approve request', 'decide', 'approver', 'block request', 'pending requests', 'check deps'],
          needs: ['requests:decide'],
          blocks: [
            { t: 'p', text: 'Open **Requests**. Pending requests are listed first, with who asked, why, how many times, and any known vulnerabilities.' },
            { t: 'shot', id: 'approver-requests' },
            { t: 'table', head: ['Action', 'What it does'], rows: [
              ['approve', 'Shows what the package pulls in, asks for a note, and adds an allow rule for the name and versions asked for. If your admin turned it on, it also offers to approve the dependencies no rule covers yet, as long as nothing is known against them.'],
              ['block', 'Asks for a reason and adds a deny rule that beats the whitelist. With no versions asked for, the whole package is blocked.'],
              ['clear', 'Takes the request off the list without a rule. If the same install is blocked again, a new request appears.'],
              ['check deps', 'Walks the dependency tree without deciding anything.']
            ] },
            { t: 'tip', text: 'Tick several requests to decide them together.' }
          ]
        }
      ]
    },
    // ------------------------------------------------------------------------------------------------ help
    {
      id: 'help', label: 'Troubleshooting',
      topics: [
        {
          id: 'troubleshooting', title: 'Troubleshooting',
          summary: 'The errors people hit most, and how to fix them.',
          keywords: ['401', 'unauthorized', 'certificate', 'self signed', 'UNABLE_TO_GET_ISSUER_CERT', 'ssl', 'timeout', 'ETIMEDOUT', 'ENOTFOUND', 'proxy', 'not working', 'help', 'error'],
          blocks: [
            { t: 'table', head: ['You see', 'Likely cause', 'Fix'], rows: [
              ['401 Unauthorized, or `npm whoami` fails', 'No token, an expired token, or a revoked token.', 'Check `NPM_TOKEN` is set in this shell. Make a new token if needed.'],
              ['npm does not use {{host}}', 'A project `.npmrc` or an `npm_config_registry` variable points somewhere else.', 'Run `npm config get registry` in the project folder to see which one wins.'],
              ['`unable to get local issuer certificate`', 'Your company uses its own certificate authority.', 'Set `NODE_EXTRA_CA_CERTS`, `PIP_CERT` or docker `certs.d` to the company CA file. Do not turn off TLS checks.'],
              ['pip: No matching distribution found', 'The project is blocked, or the name is wrong.', 'See [When something is blocked](#docs/blocked) for the curl command that shows the reason.'],
              ['docker: pull access denied', 'Not logged in to {{dockerHost}}, or the tag is blocked.', 'Run `docker login {{dockerHost}}`, then read the reason after `denied:`.'],
              ['docker: toomanyrequests', 'The image is being scanned before it is served.', 'Wait a minute and pull again.'],
              ['Yarn: 401 on some packages', '`npmAlwaysAuth` is missing.', 'Add `npmAlwaysAuth: true` to `.yarnrc.yml`.']
            ] },
            { t: 'p', text: 'Still stuck? Send your approver or admin the full error line and the time it happened. They can find the exact request in the traffic log.' }
          ]
        },
        {
          id: 'security-dev', title: 'Security habits that help',
          summary: 'Small habits that keep your code and your company safe.',
          keywords: ['security', 'best practice', 'typosquatting', 'lookalike', 'dependency confusion', 'secrets', 'safe'],
          blocks: [
            { t: 'list', items: [
              '**One token per place.** A laptop token and a pipeline token, never shared, so one can be revoked alone.',
              '**Short expiry.** A token that expires in 90 days limits the damage if it leaks.',
              '**Commit lock files.** They pin exact versions, so a new malicious release cannot sneak in.',
              '**Check names carefully.** `reqeusts` is not `requests`. {{name}} warns about lookalike names, but read the name before you install.',
              '**Walk the tree** before adding a package. See [Check before you install](#docs/check).',
              '**Never turn off TLS checks** to make an error go away.'
            ] }
          ]
        }
      ]
    }
  ]
};

export { DEVELOPER };
