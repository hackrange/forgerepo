# ForgeRepo

ForgeRepo is a private package registry that sits between your developers and the
public registries: npm, PyPI, container images, NuGet, Maven, RubyGems, Composer,
CocoaPods, Swift packages, and RPM and APT mirrors. Packages you have approved get through and get
cached. Everything else gets a clear 403 telling the developer how to ask for it.

Author: Tim Rice

Everything runs in one container: the app, the MySQL database and the cache.
The only outside piece is a reverse proxy for TLS.

## What it does

- Whitelist or blacklist, your choice, with the whitelist as the default
- More than one upstream registry, routed by pattern, so a scope can only come from one place
- Rules can be exact names, wildcards like `@acme/*`, or version ranges
- Metadata is filtered, so a blocked version is not even mentioned to npm
- Tarballs are cached on disk and checksummed against what npm published
- A PyPI index for pip, uv and poetry, behind the same rules, cache and scanning, when PyPI is switched on
- Role based access with a request and approve workflow
- Tokens carry an application and an environment, so the traffic log says which application pulled a bad version and where it is running
- IP allow list on the portal with break glass keys to get back in
- Separate allow list for npm clients, which can fetch GitHub's runner ranges itself, or take a valid token instead of an address
- Import and export of rules as JSON or CSV, with no limit on how many
- Review an uploaded package.json, lockfile, SBOM, name and version list, or zip against the rules and the advisory feed, then whitelist, blacklist or ask for what it found
- Scheduled vulnerability scanning of everything the rules allow and everything cached
- `npm audit` answered locally, and a warning in the install output, without failing a build
- Cache housekeeping that catches the database and the disk drifting apart
- Full audit trail of who changed what, what it was before and after, and whether it worked

## What you need

- Docker with the compose plugin, on Linux
- A reverse proxy for TLS, nginx or whatever you already run
- About 2 GB of disk to start with, and room for the cache to grow

Nothing else. No Node, no MySQL and no npm on the host, it is all in the image.

## Getting started

The short way. Fetch `setup.sh` onto a fresh box and run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/hackrange/forgerepo/master/setup.sh
sudo bash setup.sh --url https://npm.example.com
```

That installs docker and the compose plugin if they are missing, puts the
project in `/data/docker/npm-repo`, makes up a strong admin password and a
break glass key, builds the image, starts it and waits for the database to
finish building itself. It prints the password at the end and writes it to
`.env`.

Run it again any time. It never overwrites an existing `.env` and it never
touches your data, so it is a safe way to pick up a new version.

Options, all optional:

| Flag | What for |
| --- | --- |
| `--url https://npm.example.com` | the address developers will use |
| `--dir /opt/npm-repo` | install somewhere other than `/data/docker/npm-repo` |
| `--port 4444` | host port to publish on |
| `--name npm-repo` | container name, change it to run two on one box |
| `--no-start` | set it all up but do not start it |
| `--upgrade` | pull the latest code, rebuild the image, restart |

Tested on Ubuntu 22.04 LTS and 24.04 LTS. Debian and the RHEL family use the
same steps and should work.

### Upgrading

```bash
cd /data/docker/npm-repo
sudo ./setup.sh --upgrade
```

That pulls the branch this copy is on, rebuilds the image and restarts the
container, then waits until the app answers its own health check before it says
it worked.

Do not reach for `docker compose up -d` on its own, and `docker pull` is no help
either. Compose builds this image from the Dockerfile rather than fetching one,
and `up -d` reuses the image it already has, so new code lands in the directory
and never reaches the container. The restart works, the version does not change,
and it looks for all the world like the upgrade did nothing. Rebuilding is the
step that gets missed:

```bash
docker compose up -d --build
```

is the same thing done by hand. `--upgrade` is that plus the parts worth not
forgetting: it refuses to run over local edits rather than throwing them away,
it tags the image that was running as `npm-repo:previous` so a bad upgrade goes
back with

```bash
docker tag npm-repo:previous npm-repo:latest && docker compose up -d
```

except when the upgrade moved the database to a newer MariaDB, which the older
image cannot open. `--upgrade` tells you which case you are in, and the section
below covers the other one.

and it leaves `.env`, the data directory and the database alone. There is no
migration step to run: the app applies the schema on boot, so by the time it
answers, any new tables are already there.

Give the portal a hard refresh afterward. The page is cached for five minutes,
and a stale copy of it is the other way an upgrade looks like it did nothing.

### Moving to Ubuntu 26.04 and MariaDB 11.8

The image is built on Ubuntu 26.04 LTS. Earlier images were Debian 12 with MariaDB
10.11, and the first start of this one on their data upgrades the database to
MariaDB 11.8. Upgrade the usual way, pulling first so the new `setup.sh` is the
one that runs:

```bash
cd /data/docker/npm-repo
git pull --ff-only
sudo ./setup.sh --upgrade
```

A copy of `setup.sh` from before this release still upgrades correctly, but it
waits only three minutes for the container and its advice on failure is always
to retag, so pulling first is the better way. What happens:

- `setup.sh` checks, before stopping anything, that the new MariaDB is not older
  than the data and that there is room for a backup the size of the database.
  If either check fails it stops with the old container still running.
- it stops the old container with two minutes for the database to shut down
  cleanly.
- the new container backs the database up to
  `backups/before-mariadb-11.8...-from-10.11....sql.gz` in the data directory or
  volume, checks the copy is complete, and will not upgrade without it.
- it runs `mariadb-upgrade` once and records that it did, so later starts skip it.
  If it is interrupted, the next start carries on; a retry after a failure uses
  the backup already taken rather than taking another.
- the app starts and applies its schema as usual, and `setup.sh` tells you where
  the backup is.

**This one cannot be put back by retagging `npm-repo:previous`.** Once MariaDB 11.8
has upgraded the data, 10.11 can no longer open it. The new image refuses to start
on data from a newer server than it carries, but the old image has no such check.
To go back, set the upgraded database aside, start the old image on an empty one
and restore the backup into it. With `DATA_PATH=./data`:

```bash
cd /data/docker/npm-repo
docker compose down
mv data/mysql data/mysql.after-upgrade
docker tag npm-repo:previous npm-repo:latest && docker compose up -d
# wait until docker compose ps says healthy, then
gunzip -c "$(ls -t data/backups/before-mariadb-*.sql.gz | head -1)" | docker exec -i npm-repo mariadb
docker restart npm-repo
```

With a named volume (`DATA_PATH=npm-repo-data`, the default). Compose puts the
project name in front of the volume's, so it is read off the container first
rather than typed:

```bash
cd /data/docker/npm-repo
VOL=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' npm-repo)
echo "$VOL"           # npm-repo_npm-repo-data on a default install; stop if empty
docker compose down
docker run --rm --entrypoint sh -v "$VOL":/data npm-repo:previous -c 'mv /data/mysql /data/mysql.after-upgrade'
docker tag npm-repo:previous npm-repo:latest && docker compose up -d
# wait until docker compose ps says healthy, then
docker run --rm --entrypoint sh -v "$VOL":/data npm-repo:previous -c 'gzip -dc "$(ls -t /data/backups/before-mariadb-*.sql.gz | head -1)"' | docker exec -i npm-repo mariadb
docker restart npm-repo
```

Keep `mysql.after-upgrade` until you are sure, then delete it. Both ways were
rehearsed on a copy of a production database, along with an upgrade under
writes, one after a hard kill, a kill during the backup and during the upgrade,
a failed upgrade retried, a full backup disk and too little room: every table
came back the same.

### The long way

If you would rather do it yourself:

```bash
git clone https://github.com/hackrange/forgerepo.git npm-repo
cd npm-repo

cp .env.example .env
$EDITOR .env          # set PUBLIC_URL at the very least

docker compose up -d --build
```

First boot takes about thirty seconds while the database is built. Watch it with
`docker compose logs -f` if you want to see it happen.

Unless you put one in `.env`, the admin password is made up on first boot and
printed once in the log. It works for one sign in, then the portal asks for
your own:

```bash
docker compose logs | grep "temporary password"
```

Then put a proxy in front. There is a worked nginx example in
`nginx/npm-repo.conf.example`, including how to get a certificate without the
usual chicken and egg problem.

Open `https://your-host/_admin/` and sign in as the `ADMIN_USER` from your `.env`.
`https://your-host/admin/` is the same portal at a shorter address, and behaves
exactly the same in every respect, the allow list and break glass included. The
one thing `/admin` leaves alone is npm asking for the published package called
`admin`, which still reaches the registry.
The portal makes you pick a new password before it will let you do anything.

Everything after that is done in the portal. There are no config files to edit
for day to day work.

### Pointing npm at it

```bash
npm config set registry https://your-host/
```

Or per project, in a `.npmrc` next to your `package.json`, which is usually the
better idea because it travels with the repo:

```
registry=https://your-host/
```

If you turn on **Require tokens** on the Tokens page, developers also need a
token from that same page:

```
//your-host/:_authToken=nrt_xxxxxxxx
```

Nothing else changes for npm. `npm install` resolves as it always does, among the
versions the rules allow, and the `resolved` addresses written into
`package-lock.json` point at this box, so `npm ci` rebuilds from the lockfile
through it too, with npm checking every tarball against the integrity the lockfile
recorded. A package the rules block fails the install with a 403 that names the
reason.

### Pointing pip at it

Once **PyPI** is switched on and a PyPI registry is added, both under
Settings → Registries (`https://pypi.org` for the public one), the box is a
Python package index as well, at `/pypi/simple/`:

```bash
pip config set global.index-url https://your-host/pypi/simple/
```

From then on pip is used the way it always is:

```bash
pip install requests
pip install requests==2.32.5
pip install "requests>=2.30,<3"
pip install -r requirements.txt
```

pip resolves among the releases the rules allow, since the rest are not listed,
so a range steps around a blocked release to the next one that satisfies it, and
pinning a blocked release finds nothing to install. `Requires-Python` and yanked
releases work as they do on PyPI: pip skips releases that need a newer Python than
the one running it, and a yanked release is only taken when it is pinned exactly,
with pip's warning and the reason it was yanked.

uv, poetry and anything else that takes an index address use the same one. With
**Require tokens** on, the token goes in the address, which pip also reads from
a keyring or `.netrc` if you would rather not write it down:

```
https://__token__:nrt_xxxxxxxx@your-host/pypi/simple/
```

It speaks the index the way PyPI does: the HTML and JSON project pages (PEP 503
and 691, with sizes and versions from PEP 700), metadata files so resolvers can
read dependencies without downloading wheels (PEP 658), and the JSON API at
`/pypi/pypi/<project>/json`. **Check a package**, with the type set to PyPI, also
shows what a release is: its Requires-Python, license, Requires-Dist, extras,
project URLs, classifiers, and each file with its size, upload time and SHA-256,
read from the JSON API or from the release's own metadata file. Releases the rules do not allow are left out of all
of them, so pip never sees them, and every file is checked against the hash its
index published before it is cached or served. A private index that wants a
username and password takes them in the registry's token field as
`user:password`. Files are fetched from wherever the index lists them, which for
PyPI is files.pythonhosted.org, but a file on a host other than the registry's
own has to be on a public address: an index page cannot send the box to
something on your internal network.

### Installing it on another server

The app is one container and one data directory, so there is not much to it.

For a plain second instance, clone the repo, write a new `.env` and start it.
Then copy your rules across with **Import / export** in the portal: export the
whole config on the first box, import it on the second. That moves the rules,
the settings and both ip lists. Users, tokens and break glass keys are never
in an export, so make those again on the new box.

To move an existing instance somewhere else, take the data with you:

```bash
# on the old server
docker compose down
tar czf npm-repo-data.tar.gz -C ./data .

# on the new one, after cloning and writing .env with DATA_PATH=./data
mkdir -p data && tar xzf npm-repo-data.tar.gz -C ./data
docker compose up -d --build
```

If you are on a named volume rather than a host directory, get at it like this:

```bash
docker run --rm -v npm-repo_npm-repo-data:/data -v "$PWD":/out \
  ubuntu:26.04 tar czf /out/npm-repo-data.tar.gz -C /data .
```

## How a decision gets made

For any package the rules are sorted and the first match wins:

1. Highest priority first
2. Then the most specific pattern, so an exact name beats `@acme/*`, which beats `*`
3. Then deny before allow, if two rules are otherwise equal

If nothing matches at all, whitelist mode blocks it and blacklist mode allows it.

### Upper case in package names

npm stopped accepting upper case in new package names in 2017, but the ones
registered before then are still published and still installed. `JSONStream` and
`Base64` are the two you are most likely to meet.

Case is part of the name, not decoration. `JSONStream` and `jsonstream` are two
different packages, by different authors, with different code, and npm serves
them from different urls. So the two kinds of rule treat case differently:

- a **deny** matches whatever the case, because a block you can dodge by typing
  `Event-Stream` instead of `event-stream` is not a block
- an **allow** matches exactly, because approving `JSONStream` must not also
  approve `jsonstream`, which is somebody else's code

Same idea as a deny outranking an allow: broad about what gets stopped, precise
about what gets through. Write the name the way npm spells it and it will work.
Write it in the wrong case and the allow will not match, which is the honest
answer, since npm would hand you a different package.

One limitation worth knowing: the unique key on the rules table ignores case, so
you cannot hold an allow for `JSONStream` and one for `jsonstream` at the same
version range. In practice you want one of them, not both.

### Rules for one application or environment

Every token can carry an application and an environment (Settings → Applications),
and a rule can be limited to either or both. Leave them on "every" and the rule
covers everyone, which is how all rules behaved before.

- A rule for one application or environment only applies to requests made with a
  token for it, and beats a rule for everyone at the same priority. Production can
  block something every other environment may use, and dev can use something that
  is blocked for everyone else.
- A rule for an application **in** an environment is the most specific of all.
  Priority still comes first, as it always has.
- The scope comes only from the token. Nothing a client sends can choose it, and a
  request with no token only ever gets the rules for everyone.
- Refusals name the scope, like `blocked by rule lodash in production`.
- Cache housekeeping and vulnerability scanning keep and watch anything some
  application may use, so a dev-only rule does not get its files thrown out.
  Caching a pinned rule warms it for its own application and environment.
- **Check a package** and **Show every version** take an application and an
  environment, so you can see the answer a particular token would get.
- Exports name the application and environment, and an import looks them up by name
  on the box it lands on; a name that box does not have is reported, never quietly
  widened to everyone. An application or environment with rules scoped to it cannot
  be deleted (retire it instead).

**Any-version rules cache their current version.** When an allow rule that covers
every version of one package is written (approving a request, saving a rule,
adding rules in bulk, or whitelisting from a review) and nothing of that package
is cached yet, the version that is current at that moment is downloaded in the
background: npm's `latest`, or the newest stable PyPI release that is not yanked,
with all of its files. The kill switch and the rules for that rule's application
and environment are asked first, as a warm does, so a current version something
blocks is left alone. An hourly job does the same for older any-version rules that
still have nothing cached, up to 100 at a time, and leaves a package that could not
be cached for a day before it tries again. Every attempt is in the audit trail as
`cache.current`, with whether it worked. **Cache the current version of
any-version rules** under Settings, Cache switches it off.

### Pinning versions

Every rule has an optional version range. Leave it empty and the rule covers the
whole package. Fill it in and the rule only covers matching versions, and the
rest are stripped out of the metadata before npm ever sees them.

It takes anything npm itself understands:

| Range | What it covers |
| --- | --- |
| `1.1.1` | that one version and nothing else |
| `1.2.*` or `1.2.x` | any 1.2 patch, so 1.2.0 through 1.2.99, but not 1.3.0 |
| `1.x` | anything in the 1 series |
| `^1.2.0` | 1.2.0 and up, staying on major 1 |
| `~1.2.0` | 1.2.0 and up, staying on minor 1.2 |
| `>=4.17.21` | that version or newer, no upper limit |
| `1.2.3 \|\| 1.4.5` | either of two exact versions |

So an allow rule of `call-bind-apply-helpers` with range `1.1.1` approves exactly
that release. An allow of `lodash` with `4.17.*` cuts 114 published versions down
to the 20 that match, and a request for any other tarball gets a 403 even if it
is asked for directly.

A deny with a range works the other way and only blocks those versions, leaving
the rest of the package usable. That is how you retire a bad release without
banning the package outright.

### Getting a package approved

A developer who hits a block sees the reason and a link to the portal. They open
a request, an approver looks at it and approves, and an allow rule is written for
them. Blocked installs also open a request on their own, so approvers can see
what people are actually reaching for.

Before approving, use **Check** to walk the dependency tree. A package with 60
dependencies needs all 60 allowed or the install still fails, and that screen has
a button to allow the whole set in one go.

The walk says what every package in the tree is, most serious first: **blocked**
(a rule, the kill switch, a rejected or strict quarantine hold, or a blocked
license), **known advisory**, **no rule approves it** (blacklist mode still serves
it) or **never seen on this registry** (nothing cached, so no scan, license or
integrity evidence yet), and counts them, direct and transitive apart.

Approving a request walks its tree first and puts those counts in front of the
approver. Nothing behind it is approved on its own. **Approving a request can
approve its clean dependencies too** (Settings → Policy, off by default) lets the
approver say yes to the ones no rule approves yet and nothing is known against:
each gets an allow rule pinned to the version the walk resolved, after the
advisory feed is asked about it again. Blocked, vulnerable, held and killed
packages are never approved this way, and if the feed cannot answer about all of
them none are. The rules are in the audit trail as
`request.approve.dependencies`.

Every row says what is known against the versions it would let in. That answer
cannot come off the Vulnerabilities page. That list covers what the rules pin
and what the cache holds, and a package being asked for is neither, so the
versions are worked out from the package's own metadata and put to the advisory
feed while you are looking at the row. A request with a range on it is only asked
about inside that range, since that is all you are being asked to allow, and the
newest ten of the matching versions are checked. Hover the cell for exactly which
versions were looked at, which advisories came back and what they are fixed in.

**No Known Vulnerabilities** means the feed answered and had nothing against
those versions. If the feed could not be reached the cell says **could not
check** instead, because an unanswered question is not a clean answer. Nothing
looked up this way is added to the Vulnerabilities page: that page is this
registry's own exposure, and a package nobody has approved yet is not part of it.

**Asked by** is who to go back to. A portal request carries the account, its
full name and its email address, and the address is a mailto link. A request that
an install opened on its own carries the npm token it was using, and the address
it came from when there was no token at all. Repeats fold into the one row, so
the first person to hit it stays on it, and a row that started anonymous picks up
the account and token from the first authenticated hit that follows.

Four things can happen to a request, and they are on the row itself:

- **approve** says what the package brings in behind it, then writes the allow rule and
  marks the request approved
- **block** writes the deny rule, at priority 1000 so it beats the whitelist, and
  marks the request blocked. If the request named versions only those are
  blocked; with no range it is the whole package. Deciding and enforcing happen
  in the same move, so the answer and the rule cannot drift apart
- **clear** takes the row off the list and writes nothing at all. For typos,
  packages somebody stopped needing, noise from an install that has since been
  fixed. There are tick boxes and a **Clear selected** button for doing a page
  of them at once
- **check deps** walks the dependency tree first, which is the one to use before
  approving something you have not seen before

Clearing deletes the row rather than settling it, so the list only ever holds
live questions. Nothing that matters is lost: the audit trail keeps who cleared
what and when, and since clearing decides nothing there is no decision to look up
later. It is also not a way to silence a package. The next blocked install opens
a fresh request, because the row that gets bumped instead of created has to be a
pending one and there is no longer a row of any kind.

## Reviewing a file before it gets near the registry

The **Check** page takes a file and tells you what this registry makes of
everything in it. Drop in a `package.json`, `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock` (classic or berry) or `pnpm-lock.yaml`; a
`requirements.txt` (or any `requirements*.txt`, `*.in` or constraints file),
`poetry.lock`, `uv.lock`, `pylock.toml` or `Pipfile.lock`; a CycloneDX SBOM in
JSON or XML, or an SPDX JSON one; a plain list of names and versions; or a zip
holding any number of them, and press **Review it**.

npm packages are judged by the npm rules and PyPI packages by the PyPI rules, and a
bill of materials is split by each component's purl: `pkg:npm` and `pkg:pypi` are
reviewed, anything else is counted and left out. A requirements file is read line by
line: `-r` and `-c` includes are reported rather than followed, and editable installs
and packages from a url are left out and counted. Lockfile entries that come from a
workspace, a path or git are left out the same way. A CycloneDX XML file that declares
a DOCTYPE or entities is refused without being read. The CSV export has an
`ecosystem` column at the end, and allow, deny and approval requests from a mixed
review go up once per ecosystem.

A list is the easy case and needs no ceremony. Csv, tab separated, or columns
lined up with spaces, with or without a header naming them:

```
package                                version
@babel/helper-string-parser            7.27.1
@babel/helper-validator-identifier     7.28.5
@babel/parser                          7.29.3
```

Blank lines and lines starting with `#` are ignored. Anything else on a line
that is not a name and a version is counted and reported at the top of the
review, so a file half of which was dropped says so rather than coming back
looking short.

A bill of materials is the awkward case, because it usually describes a whole
estate rather than a dependency tree. The repositories it searched, the tool
that wrote it and the application it is about are all components in the same
array as the packages, and the packages themselves can come from any ecosystem.
Only the npm ones are reviewed. The rest are counted and named in the notes:
this registry has rules about the npm namespace and nothing else, and judging a
pypi package by them would be an answer to a question nobody asked.

If a file will not parse at all, the reason says which kind of problem it is. A
document that stops in the middle is reported as cut short, with the byte it
stopped at, rather than as a formatting mistake, because those have very
different fixes and the parser cannot tell them apart on its own: it reports the
first thing it could not read, and for a file that simply stops, that is the end
of the file.

Every package it finds comes back as one of three answers, worst first:

- **blocked** a deny rule wins for that name and version
- **whitelisted** an allow rule wins
- **needs review** no rule decides it, so the policy mode does

and then the distinctions that make the list worth reading rather than counting:

- **whitelisted, vulnerable** it matches a deny rule, but an allow rule of higher
  priority lets it through anyway. Worth confirming that exception is deliberate
- **at risk** the rules block other releases of this package, so it is known to
  ship bad ones, and the version here has never been vetted either way. Rank
  these above ordinary drift
- **unapproved version** the rules know the name but not this version, which is
  usually a dependency that has drifted off the approved list

A declared range is treated as the open question it is. `^4.17.0` names no
release until npm resolves it, so a range that merely overlaps a deny rule is
reported as exposure rather than counted as blocked: npm may or may not install
an affected version, and the fix is to pin or raise it.

### It checks the versions, not just the rules

Before the report is drawn, every exact version the file pins is checked against
the same advisory feed the Vulnerabilities page uses. That is a different
question from what the rules say, and both answers are on the row. A package can
be perfectly whitelisted here and still be a critical CVE, and that pairing is
the whole reason to review a file in the first place.

Only pinned versions can be checked. A range names no release to ask about.

Anything found that this registry would actually serve is added to the
Vulnerabilities page as well, since it is our exposure too. Anything found that
this box would not serve is reported to whoever uploaded the file and left at
that, so reviewing another team's lockfile does not fill your own vulnerability
list with their problem.

### Nothing is left on disk

The upload is read in memory, the zip is inflated entry by entry in memory, and
none of it is written anywhere. There is no working directory to tidy up, and
nothing is left behind if the request dies halfway through. The report lives in
the browser until you review another file or navigate away.

Files that are not manifests are skipped and named, files that will not parse are
reported rather than passed over, and every ceiling it hits is printed on the
page. A truncated review never reads like a clean one.

### Who can do what with the results

- **anybody who can sign in** can review a file and export the result as JSON or
  CSV. The export holds every package, not the first page of them
- **a developer** can tick the packages that are not approved and ask for them in
  one go. Anything already approved is left out rather than asked for again, and
  anything they have already asked about is bumped rather than raised twice
- **an approver or admin** can tick packages and write the allow or deny rules
  there and then, either pinned to the version reviewed or covering the package
  outright. Blocked rows are not tickable by anybody, see below

The same tick boxes and the same three actions are on the dependency tree walk
further down that page, so a tree you have just looked at can be decided on
without retyping any of it.

### A blocked package cannot even be ticked

A row that a deny rule matches has no tick box on either the review or the tree
walk. Not a box that fails when you press it: no box. A blocked version is never
whitelisted from this page, so there is nothing to select it for, and offering
the box only invites the click.

The distinction that matters here is between blocked and not approved yet. A
package a deny rule names is a decision somebody already made, and it stays
made. A package no rule mentions is the decision being asked for, and those
stay tickable, or the page would be useless: requesting and approving them is
the whole point of it.

The same line is drawn everywhere it could be crossed. **Allow all packages that
are not approved yet** on the tree walk leaves blacklisted ones alone and says
how many it left, so a blocked package is not whitelisted by being in the same
tree as something somebody wants. The server refuses it too, on the version that
was reviewed rather than on whether the new rule pins it, so it holds for
anything talking to the API as well as for the page.

Taking a package off the blacklist is a decision to make on the Rules page, where
the deny rule and the note saying why somebody wrote it are both in front of you,
not a side effect of working through a list of a hundred packages.

Blacklisting from the review always works. It is only the other direction that
is one-way.

## Roles

| Role | What they can do |
| --- | --- |
| viewer | Read the rules, packages and vulnerabilities, review an uploaded file, and export the rules as json or csv |
| developer | The above, plus ask for packages, including asking for everything a reviewed file needs in one go, walk dependency trees, and manage their own tokens |
| publisher | The above, plus publish npm and PyPI packages under the reserved names, usually a CI account |
| approver | The above, plus edit rules, decide on requests and waivers, purge packages, and whitelist or blacklist straight from a review or a tree walk |
| admin | Everything, including users, settings, access control, traffic and the audit trail |

Permissions are checked on the server for every request. The portal hides buttons
you cannot use, but that is only tidiness, it is not the control.

Settings are admin only to **read** as well as to write, and so are the two ip
allow lists, the break glass keys, the upstream registries and the mail log.
Credentials never leave the box either way, but the allow list and the key
inventory together describe how somebody would get at the portal, and that is
not something a developer account needs to see. Anyone below admin gets a 403
from those endpoints and does not see the pages in the menu.

### Acting as another user

An admin can use **impersonate** on the Users page to see and use the portal
exactly as that person does. It is for support: checking what a developer can
actually see, or reproducing what they ran into.

- Only an admin can do it, and never to another admin, to themselves, or to a
  switched-off account. It cannot be started from inside another impersonation.
- The admin gets that user's role and nothing more. Anything they do is done as
  that user, and the audit trail records it as `admin as jsmith`. The start and
  the end are recorded too.
- It cannot be used to take over the account: changing that user's password is
  refused.
- A red bar stays at the bottom of every page with the time left and a **Stop**
  button. Stop puts the admin back in their own session.
- It ends by itself after 30 minutes, and the admin's own session comes back the
  next time the page talks to the server. It also ends at once if the admin is
  switched off or demoted, or if the user they are acting as is made an admin.
- **Sign out** while acting as someone signs the admin out as well.
- The admin's own session is kept in a separate cookie only the API reads, and
  handed back only if it is still a valid admin session. A copy of the
  impersonation cookie on its own can never be turned into admin access.

## Access control and break glass

By default the portal answers anyone who can reach it, and you rely on the login.
For something tighter, add your networks under **Whitelists → Whitelist Admin Portal** and switch
the filter on. The portal refuses to enable it until your own address is on the list,
so you cannot lock yourself out by accident.

Once it is on, a request from any other address gets a flat `404 Not Found`. No
redirect, no login page, no clue that there is an admin side at all.

### Whitelisting the clients

That list guards the portal. The registry has its own, on the **Whitelist
Clients** tab of the same page, with its own switch and its own set of networks. Tick it
and only the networks you list may pull packages at all. Everything else gets a
plain `403` saying its network is not accepted, because a developer staring at a
failed install needs to know why.

It is deliberately not the same list as the one above. The machines that run
installs are rarely the machines you administer from, and forcing both through
one list means opening one of them wider than you meant. That is why the two
tabs are named for who they serve: **Whitelist Admin Portal** guards the portal,
**Whitelist Clients** guards the registry.

An older setting, `acl_covers_registry`, used to point the portal list at the
registry instead. It is gone. If your box had it switched on, its networks are
copied onto the client list on first boot and that list is switched on, so the
same addresses keep the same access under the new name.

Getting this one wrong cannot strand you. It never touches the portal, so you
sign in as usual and undo it. The api will not let you switch it on with an
empty list, or remove the last network while it is on, since either would leave
a filter that looks like protection but is not.

#### GitHub Actions, and other clients with no fixed address

A workflow on a GitHub hosted runner comes out of Azure, from whichever range
the runner landed in that morning, and there are thousands of them. There is
nothing useful to type into the list, so the list goes and reads them instead.

Tick **Allow GitHub SaaS** under Whitelist Clients. The ranges GitHub publish at
`https://api.github.com/meta` are fetched, stored alongside the networks you
typed, and rechecked every day. You can pick which parts of that document to
take: **Actions runners** is the one a blocked workflow needs, with the macOS
runners listed separately by GitHub and **Codespaces** there for installs run
from inside a codespace. **Fetch them now** does it on the spot, and says what
came back.

The section of the document is the `actions` key, which is what
`curl -s https://api.github.com/meta | jq '.actions'` prints, so the answer you
were given was the right one. Two things it does not tell you. That array holds
IPv6 as well as IPv4 and both are stored, since a runner reaching a
dual stack registry over v6 would otherwise be blocked by a list that looks
complete. And it is about 7,000 ranges: too many to sit in a table meant to be
read, so they live apart from the networks you typed and the page shows a count
rather than the list. They are matched by binary search over merged ranges
rather than by walking them, so the size costs nothing per request.

**What this buys, and what it does not.** Those ranges belong to every GitHub
customer, not to your organization. Anyone with a free account and a workflow
file is inside them. Ticking this says installs may come from GitHub, which is
worth saying on a registry that would otherwise refuse them, and it says nothing
at all about whose build it is. If that distinction matters, and on a private
registry it usually does, the network is the wrong thing to be asking.

A failed fetch never blocks anything. The stored ranges stay as they were, the
page says when the last attempt was and what went wrong, and the hourly job
tries again rather than waiting out the day. A feed that has never fetched
successfully has nothing in it, and nothing in it means nobody is allowed by it,
not that everybody is refused.

#### A token as the way through

The better answer to "is this really our build" is usually not an address at
all. Tick **Let a valid token through from any network** and a client holding a
token issued from this portal is served wherever it connects from, and the
network filter only judges the requests that arrive without one.

An address is a guess about who is calling and a token is an answer, so this is
the stronger check of the two, and it is the one that keeps working when a
runner moves, a developer works from a hotel, or GitHub publishes a new range
before the daily fetch has picked it up. Pair it with **Require a token from package
managers** (Settings → Registries): with that off, a request that sends nothing is still judged on its
address alone, which is the filter you already had rather than a hole in it.

Tokens are made per person under Tokens, are revocable one at a time, and every
request records which one was used. A network cannot be revoked and does not say
who was behind it.

The way back in is a break glass key, which is a UUID you generate ahead of time:

    https://your-host/_admin?bgt=00000000-0000-0000-0000-000000000000

or the same key at `https://your-host/admin?bgt=...`, which lands you back on
`/admin/` instead.

A good key mints a short lived grant tied to the address that used it, drops it in
a cookie, and bounces you to a clean URL. A bad key gets the same 404 as no key,
so nobody can use it to hunt for live keys. Keys are stored as a SHA-256, are
shown once when created, and every attempt is written to the audit log. nginx is
set up to write `bgt=[redacted]` to its access log rather than the real key.

Keep at least one key somewhere safe and offline. If you enable the filter, then
your office IP changes, a key is the only thing that gets you back in short of a
shell on the host.

## Scanners, and why they report this box

Point a web vulnerability scanner at a registry and it will report exposed
config files. It is wrong, but it is wrong for an interesting reason, and it
will be wrong again on the next scan unless you do something about it.

npm's namespace has a real published package under very nearly every filename
worth guessing. `config.json`, `index.php`, `package.json`, `settings.json`,
`phpmyadmin`, `server-status`, `server-info` are all real packages. A scanner
walks a webserver wordlist, asks this registry for `/config.json`, and gets a
`200` with a JSON body, so it reports a leaked config file.

Nothing was read from disk. That body is npm metadata, proxied. The giveaway is
in the response itself: `_id`, `_rev`, `dist-tags` and `versions` are CouchDB
fields, and the `_rev` will match `registry.npmjs.org` byte for byte. That
comparison settles the argument faster than any explanation.

Two things make it stop:

**Enforce the whitelist.** On a box in whitelist mode none of those names are
approved, so they never reach npm and never come back with a body. If your
registry is answering `200` for `/phpmyadmin`, check Mode and Audit only in
Settings, because it is currently willing to fetch any public package for
anybody who can reach it.

**Only answer package managers**, in Settings → Registries. Anything that does not
announce itself as a package manager gets a flat `404`. It is off by default
because it is a real behavior change: anything pulling packages with `curl`, or
a bot with a user agent of its own, stops working the moment it goes on. Check
your build scripts first.

Two related reports you may also see, both harmless:

- **WebDAV with PUT and DELETE.** The registry registers those methods in order
  to refuse them, and returns `405 this is a read only mirror` for both. It no
  longer advertises them in the `OPTIONS` response, which is what the scanner
  was reading.
- **An OAuth callback with no state parameter.** There is no OAuth here.
  `/oauth/callback` is not a valid package name, so it answers `400`, and the
  scanner read the `400` as a failed check.

## Where the data lives

One place, set by `DATA_PATH` in `.env`:

```
mysql     the database, so rules, users, requests and the logs
cache     the downloaded tarballs and the cached metadata
backups   room for dumps
```

The default is a docker named volume called `npm-repo-data`. That is the safest
default because it behaves the same on every distro and does not care about
SELinux, which otherwise blocks a host directory mount on RHEL, Rocky and Fedora
until you relabel it.

Set `DATA_PATH=./data` instead if you would rather have a plain directory you can
see and back up with ordinary tools. On an SELinux host, relabel it once:

```bash
sudo chcon -Rt svirt_sandbox_file_t ./data
```

One trap worth knowing either way: **`docker compose down -v` deletes a named
volume and everything in it**, including your rules and users. Plain
`docker compose down` is safe, and so is rebuilding the image. A host directory
survives all of it.

Nothing is ever written into the container layer, so the image is disposable.

### Keeping the disk in check

The tarball cache grows and nothing evicts it on its own. Every approved version
of every package stays until you clear it. Keep an eye on it:

```bash
docker exec npm-repo mariadb -B npmrepo -e \
  "SELECT COUNT(*) files, ROUND(SUM(size)/1048576) mb FROM tarballs;"
```

The Packages page will purge whatever you tick, and Settings has a button to
empty the lot. Clearing the cache costs nothing but the next download.

### Artifacts and the blob store

Every cached file, npm or PyPI, is stored once under its SHA-256:

```
cache/blobs/sha256/ab/cd/abcd1234...
```

and gets a row on the **Artifacts** page: package, version, filename, digest,
size, which registry it came from, when it was first seen and how often it has
been downloaded. Two packages shipping the identical file share one blob.

The digest a file is first seen with is the one it keeps. If the same file comes
back from the same registry with different bytes, the original keeps being served
and an integrity alert is raised (below). If a package is routed to a different
registry, the copy from the old one is retired and the new one takes its place.

The old `cache/tarballs` and `cache/pypi` paths are still there, as hard links to
the blobs, so they take no extra disk. That is what lets you roll back to the
previous release without losing the cache. Files cached by an older release are
moved into the blob store in the background after the upgrade; the Artifacts page
shows progress while that runs, and a restart just picks up where it stopped.

From an artifact's detail you can **Check the bytes** (re-hashes the blob; a copy
that no longer matches is thrown away and downloaded again) or **Purge** that one
file.

**Properties** are searchable `name=value` notes on a package version, or on every
version of a package: `owner=security`, `criticality=high`, `business-unit=digital`,
`review-date=2026-09-12`. Approvers and admins set and remove them from an
artifact's detail or through `PUT /_api/properties`; anyone who can see the
Artifacts page reads them. A value set on a version wins over the same name set on
its package. Names are lower case letters, digits, dots, dashes and underscores; a
value is one line of plain text up to 255 characters, and a package or version
holds at most 50. **Property** on the Artifacts filter takes a name (`owner`) or a
name and value (`owner=security`). Every change is in the audit trail as
`property.change` with the values before and after.

**Lifecycle stages** say where an exact version stands: `quarantine`,
`development`, `test`, `approved`, `production` or `blocked`. Approvers and admins
move a version from an artifact's detail or `POST /_api/lifecycle/move`, always
with a reason; every move is kept with who, when and why, and is in the audit trail
as `lifecycle.move`. A stage is only a label, the file is never copied or moved.
**Stage** on the Artifacts filter lists the files at one stage. With **Enforce
lifecycle stages** on (Settings, off by default) a `blocked` version is refused to
everyone, and a token in a production environment only gets versions moved to
`production`, so anything not promoted yet, or with no stage at all, is left out
of its metadata and refused by name. Rules still apply first; a stage never lets
in something a rule blocks.

**SBOMs** come out of the cache in CycloneDX 1.5 JSON or SPDX 2.3 JSON. From an
artifact's detail, or `GET /_api/artifacts/<id>/sbom?format=cyclonedx|spdx`, you get
that one file with its SHA-256 and license, and its direct dependencies: each is
pinned to the newest cached version its range allows, with that version's file
hashes, and one with nothing cached is listed by the range it asks for. Nothing is
fetched to write one; a version whose metadata is not cached says its dependencies
are unknown rather than listing none. The serial number is worked out from the file,
so the same file always gets the same one. On the **Consumers** page, **SBOM of an
application** (`GET /_api/sbom/application?application=Checkout&environment=production`)
lists every version that application downloaded, from the consumption record, with
the hashes of the files still cached. That one needs the same access as the
Consumers page and is in the audit trail as `sbom.export`.

Every package type is in them, each with its own purl (`pkg:npm`, `pkg:pypi`,
`pkg:nuget`, `pkg:maven`, `pkg:gem`, `pkg:composer`, `pkg:cocoapods`, `pkg:swift`,
`pkg:rpm`, `pkg:deb`, `pkg:oci`). Each version's direct dependencies are read from
its own metadata: the npm packument, the PyPI JSON, the NuGet dependency groups, the
Maven pom (properties filled in, dependencyManagement left out, test and provided marked
optional), the RubyGems info line, Composer's `require` (without php and the extensions),
the podspec, the `.package(...)` entries in Package.swift, and Debian's Depends and
Pre-Depends (the first of each alternative). An RPM asks for capabilities rather than
packages, so its dependencies are still reported as unknown. Anything with a matching
cached version is pinned to it with its file hashes; the rest are listed by the range they
ask for.

**Images** have an SBOM of what is inside them: **SBOM of what is inside** on an image's
dependency tree, or `GET /_api/sbom/image?repository=library/nginx&reference=<tag or
digest>&format=cyclonedx|spdx`. It lists every package the image scan found: OS packages
by their source package as `pkg:deb`, `pkg:apk` or `pkg:rpm` with the distro
(`pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=source&distro=debian-12`), plus the npm and
Python packages installed in the image. A multi-platform list covers each platform image,
with a package found in only some of them marked with which. Only images this box holds
are described, nothing is fetched to write one, and a platform image not scanned yet is
named in a note rather than shown as empty. In an application's SBOM, each image it pulled
carries its contents nested under it (CycloneDX nested components, SPDX `CONTAINS`).
docker and skopeo only send their login when a registry asks for it, so image pulls are
tied to an application's token, and show up in its SBOM, only with **Require a token from
package managers** on.

**Reserved names** are the npm scopes and PyPI projects that belong to your
organization: an exact name, a scope like `@acme/*`, or a prefix ending in `*` like
`acme-*` (PyPI names fold `-`, `_`, `.` and case as PyPI does). A reserved name is
never fetched from any upstream registry, not even a copy cached before it was
reserved, and npm search leaves public packages under those names out. Nobody can
register the same name on a public registry and have it installed here instead
(dependency confusion). Admins add and remove them under Settings, Registries, or
through `/_api/private-names`; anyone signed in can see the list, and every change is
in the audit trail as `private_name.add` or `private_name.remove`. Until something is
published under a reserved name, asking for it answers 404 and says why.

The **publisher** role is a developer who may also publish packages under the
reserved names, usually the account a CI pipeline's token belongs to. Approvers and
admins can publish too.

### Container images

With **Container images** switched on under Settings, Package types, this box also
answers `/v2/`, so `docker pull`, `podman` and `skopeo` can pull through it:

```bash
docker pull npm.example.com/library/nginx:1.25
```

Add a registry for images under Settings, Registries first, the same way npm and
PyPI upstreams are added: a name pattern decides which repositories it serves, so
Docker Hub, GHCR, Quay or Harbor can sit side by side. Docker Hub's anonymous token
handshake is done for you, and its own images are found under `library/`.

Everything is addressed by digest. A manifest is checked against the digest the
registry claimed, a layer against the digest its manifest named, and nothing is
stored until it matches. A tag is only ever a pointer: the digest it resolves to is
recorded, and a tag that moves is logged and counted, so `latest` changing under you
is visible rather than silent.

Rules decide repositories and references (`1.25`, a glob like `1.25.*`, or a digest),
the kill switch refuses a repository or an exact digest, quarantine holds bytes back,
and every pull is in the traffic log. `/v2/<name>/tags/list` answers with the tags
this box has seen, not everything upstream holds. Your own images can be pushed under
reserved names, see Pushing images below.

### Publishing npm packages

Point the scope at this registry and publish with a token whose owner is a
publisher, approver or admin:

```bash
npm config set @acme:registry https://npm.example.com/
npm config set //npm.example.com/:_authToken <token>
npm publish
```

Only reserved names can be published. Each publish adds exactly one new version, and
its tarball has to match the integrity in its manifest. Fields a registry has no use
for (scripts, for example) are left out of the metadata everyone reads.

A published version never changes and is never removed: publishing the same version
again is refused, and `npm unpublish` is refused. `npm deprecate` sets or clears the
message on a version, and `npm dist-tag add` and `npm dist-tag rm` move tags between
published versions (`latest` can be moved, not removed).

A new version starts in quarantine. With malware scanning on it is held until its
first scan and a clean result releases it by itself; with scanning off an admin
releases it from the Quarantine page. Everything else that applies to a mirrored
package applies to a published one: rules decide who can install it, and the license,
lifecycle stage, SBOM and audit trail all work the same. Every publish, deprecation and
tag change is in the audit trail as `package.publish`, `package.deprecate` or
`package.dist-tag`.

### Uploading PyPI packages

Upload with twine to the index root, with the token as the password:

```bash
twine upload --repository-url https://npm.example.com/pypi/ -u __token__ -p <token> dist/*
```

Only reserved projects can be uploaded, by a publisher, approver or admin. Each file
has to belong to the project and version the upload names, and when the client sends
a SHA-256 the file has to match it. Wheels and sdists of a release sit side by side.
An uploaded file never changes and is never removed: the same file name again is
refused. A new file starts in quarantine exactly like an npm publish, and pip sees it
on the project page once it is released. Uploads are in the audit trail as
`package.publish`.

```bash
docker exec npm-repo mariadb -B npmrepo -e \
  "SELECT ecosystem, COUNT(*) files, ROUND(SUM(size)/1048576) mb FROM artifacts GROUP BY ecosystem;"
```

### Image signatures

A trust policy (Settings → Registries → **Image signatures**) says that the images of
a repository (`library/nginx`, `acme/*`, or a prefix ending in `*`) must carry a
[cosign](https://github.com/sigstore/cosign) signature from someone you trust:

- **public keys**: PEM, the `cosign.pub` that `cosign generate-key-pair` writes
  (ECDSA, Ed25519, RSA of 2048 bits or more);
- **keyless signer identities**: an OIDC issuer and a subject, for instance
  `https://token.actions.githubusercontent.com` and
  `https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main`. A `*`
  may end an address that names its owner (`https://github.com/acme/*`) or stand for
  the name in an email (`*@acme.com`), never more than that.

**require** refuses a manifest pull of an image nobody trusted signed; **warn** serves
it and logs it. The signature comes from the `sha256-<digest>.sig` tag next to the
image, fetched from the same registry and kept like any manifest. A keyless signature
passes only if its Fulcio certificate chains to the Sigstore roots shipped in
`app/src/images/sigstore-trusted-root.json` (the signer's own chain is ignored), its
Rekor signed entry timestamp verifies, the Rekor entry is this signature over this
payload by this certificate, and it was logged while the certificate was valid. The
signed payload has to name the exact digest being pulled. SCTs are not checked; the
Rekor entry already proves the signature was logged. A signed list covers the platform
images it names. Results are kept per digest and per version of the policy; a failure
is retried after ten minutes.

Both layouts cosign uses are read. cosign 2 writes a `sha256-<digest>.sig` tag, which is
what most public images, cosign's own included, still carry. cosign 3 writes a Sigstore
bundle instead, under the referrers tag `sha256-<digest>` next to the image: a DSSE
envelope over an in-toto statement naming the image digest, signed with the same keys or
the same keyless identities. The `.sig` tag is tried first and the bundle second, so an
image carrying either passes, and a refusal names what was wrong with both. A bundle
carries its own Rekor entry, which is checked the same way as the older one's.

### What a publish may not carry

Everything published, uploaded or pushed as a package (npm, PyPI, NuGet) is read
before it is stored:

- **Refused outright**, with a 400 that says why: an archive built to trick whatever
  unpacks it. A path that climbs out with `..`, an absolute path or drive letter, a
  symlink or hard link, a device file, a name that appears twice, a zip whose central
  directory and local header name a file differently, a zip64 file, or one that
  unpacks past 512MB.
- **Held**: anything that looks like a secret. Private keys, AWS, GitHub, GitLab,
  npm, PyPI, NuGet, Slack, Stripe, Google and Azure keys, ForgeRepo tokens, passwords
  in connection strings, `.env` files (not `.env.example` and friends), `.npmrc` and
  `.pypirc` files with a login, SSH keys, saved git credentials and certificate
  stores. The hold has the source `hygiene`, refuses in both quarantine modes, is
  hidden from metadata and is never released by a clean scan. The finding names the
  file and the kind of secret, never the value. npm prints it as a notice, NuGet in
  its answer, twine in the response body.

**Settings → Policy → Secrets in what is published here** is `hold` (default),
`warn` (logged only) or `off`. Archive tricks are refused whatever it says.

Pushed **images** are not read at push time, because a layer is bytes rather than a
package. Put `secrets` on the scanner list (Settings → Malware) and every file this box
keeps is read for the same things, layer by layer, including images you push and images
you pull. A find is `SUSPICIOUS`, so the quarantine setting for suspicious files decides
what happens, and the finding names the file and the kind of secret, never the value.
Public packages carry test keys by the thousand, which is why it is off unless you ask
for it.

### Pushing images

Reserve an image namespace under Settings, Registries, Reserved names (Docker,
`acme/*`), then push with a token whose owner is a publisher, approver or admin:

```bash
echo "$PUBLISH_TOKEN" | docker login npm.example.com -u ci-release --password-stdin
docker build -t npm.example.com/acme/storefront:1.4.0 .
docker push npm.example.com/acme/storefront:1.4.0
```

Only reserved names can be pushed, and a reserved name is never fetched from an
upstream, not even a copy cached before it was reserved. Every blob is hashed on the
way in and refused unless it is the digest docker named. A manifest may only name
blobs this repository holds, at the sizes it says, and foreign layers that live
somewhere else on the internet are refused. A blob on the kill switch is refused at
the door.

Every blob is held in quarantine until its malware scan is clean, in both quarantine
modes, so a pull of a fresh push gets `toomanyrequests` until then. With scanning off
an admin releases it from the Quarantine page. A pushed tag never moves: pushing other
content under it is refused (`latest` excepted), and nothing pushed is deleted. Pushes
are in the audit trail as `package.publish` and in the traffic log.

An upload belongs to whoever started it and to its repository, anyone else gets
`BLOB_UPLOAD_UNKNOWN`. One user can keep 32 uploads open, an upload untouched for an
hour is swept, and a pushed blob no manifest names is removed a day later.

With image names reserved, a docker ping without a login is answered with docker's
token challenge (`Bearer realm=.../v2/token`). That is how docker learns to send its
login when it pushes. A good login gets a five minute bearer that stands in for the
token, only its hash is stored, and it stops working the moment the token is revoked.
No login gets an anonymous bearer that pulls exactly as no login always did. With
Require a token on, nothing changes: every client already logs in with Basic auth.

Layers are big, so the reverse proxy needs room for them, see below.

### NuGet feeds

With **NuGet feed** switched on under Settings, Package types, the box answers
`/nuget/v3/index.json` for dotnet, nuget.exe and Visual Studio. Add a NuGet registry
under Settings, Registries (`https://api.nuget.org/v3/index.json`, or a private feed's
`index.json` with `username:token`), write rules, and point `nuget.config` at it:

```xml
<configuration>
  <packageSources>
    <clear />
    <add key="company" value="https://npm.example.com/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <company>
      <add key="Username" value="dana" />
      <add key="ClearTextPassword" value="%REPO_TOKEN%" />
    </company>
  </packageSourceCredentials>
</configuration>
```

A package is summed up from the feed's registration pages once (its own spelling of
the id, every version, listed or not, when it was published, its license and its
dependencies) and kept for the packument TTL. Both the version list dotnet restore
reads and the registration dotnet add package reads come from that summary and go
through one filter: kill switch, quarantine, rules, safe resolution and cooling off,
so the two never disagree. Every `.nupkg` is checked again when it is asked for,
streamed to disk, hashed, refused unless it is a zip, then scanned like any file.

Ids fold to lower case for matching, so a rule, a kill or a request matches however
it was typed, while the stored name keeps the feed's spelling, which OSV needs to find
advisories. A bare version in a rule is that exact version; NuGet ranges
(`[13.0,14.0)`), floating versions (`13.*`) and comparators (`>=13.0 <14`) work too.
dotnet prints the reason for a refusal from the `X-NuGet-Warning` header.

The feed's service index decides where its package and registration addresses are,
and they have to be https (or http when the feed itself is). A registration page on
another host is never fetched. Search is not offered yet. `dotnet nuget push` is, to
reserved package ids; see [Pushing NuGet packages](#pushing-nuget-packages).

### Pushing NuGet packages

A publisher (or approver or admin) pushes to package ids an admin has reserved under
Settings → Registries → Reserved names, like `Acme.*`. The token goes in as the API
key; the feed address is the one you restore from:

```bash
dotnet pack -c Release -o out
dotnet nuget push out/Acme.Logging.1.2.0.nupkg \
  --source https://npm.example.com/nuget/v3/index.json --api-key <token>
```

- The id, version, license and dependencies are read from the `.nuspec` inside the
  package. A `.nuspec` with a DOCTYPE or entities is refused.
- A pushed version never changes, pushing it again is a `409`, and
  `dotnet nuget delete` is refused with a `405`.
- A new push is held until its malware scan is clean (or an admin releases it),
  and it goes through the checks in [What a publish may not carry](#what-a-publish-may-not-carry).
- A reserved id is only ever answered from what was pushed here, never from nuget.org,
  not even from a copy cached before it was reserved.
- The service index stays readable without a login, so `--api-key` alone is enough
  with **Require a token from package managers** on.

### Maven repositories

With **Maven repository** switched on, the box answers `/maven/` for mvn, Gradle and
sbt. Add a Maven registry (`https://repo1.maven.org/maven2`, or a Nexus or
Artifactory repository with `username:password`), write rules on `groupId:artifactId`,
and mirror everything through it in `settings.xml`:

```xml
<settings>
  <servers>
    <server><id>company</id><username>dana</username><password>${env.REPO_TOKEN}</password></server>
  </servers>
  <mirrors>
    <mirror><id>company</id><mirrorOf>*</mirrorOf><url>https://npm.example.com/maven/</url></mirror>
  </mirrors>
</settings>
```

`maven-metadata.xml` is rebuilt from the versions the rules allow, so `[2.17,2.18)`
resolves to an allowed version, and its checksums are worked out from the bytes this
box sends. Every other file is streamed in, hashed, checked against the `.sha1` the
repository publishes, and refused if it does not match. A path has to name a file of
its own artifact and version, so nothing reaches outside a package. Snapshots are not
served, and a milestone or release candidate counts as a version like any other
because poms pin them. mvn fetches its plugins through the same mirror, so they need
allow rules too; one build in audit mode lists them. mvn and Gradle print the reason
for a refusal in their error line. `mvn deploy` is not taken yet.

### Deploying to Maven

A publisher (or approver or admin) deploys to coordinates an admin has reserved under
Settings → Registries → Reserved names, like `com.acme:*`. Point the project at this
repository and put the token in `settings.xml`:

```xml
<distributionManagement>
  <repository><id>company</id><url>https://npm.example.com/maven/</url></repository>
</distributionManagement>
```

```xml
<server><id>company</id><username>you</username><password>&lt;token&gt;</password></server>
```

- Maven sends each file of a release as its own PUT. The jar and the pom are kept; the
  checksum files are **checked against the bytes that arrived** and not stored, since the
  box answers `.sha1`, `.md5`, `.sha256` and `.sha512` from what it holds.
- The `maven-metadata.xml` Maven uploads is accepted and thrown away: the version list
  this box serves is built from what was really deployed, so a client cannot write it.
- A deployed file never changes. The same bytes again is a retry and answers `200`;
  different bytes under the same name are a `409`. There is no delete.
- **Snapshots are refused**, because a snapshot is meant to change and nothing published
  here ever does.
- Each file is held until its malware scan is clean (or an admin releases it), and goes
  through the checks in [What a publish may not carry](#what-a-publish-may-not-carry).
- A reserved coordinate is only ever answered from what was deployed here, never from
  Maven Central, not even from a copy cached before it was reserved.

### Gem sources

With **RubyGems source** switched on, the box answers `/rubygems/` for Bundler and
`gem install` through the compact index. Add a RubyGems registry
(`https://rubygems.org`), write rules, and send Bundler through it with a mirror, so
the Gemfile keeps `source "https://rubygems.org"`:

```bash
bundle config set --global mirror.https://rubygems.org https://npm.example.com/rubygems/
bundle config set --global npm.example.com dana:$REPO_TOKEN
```

Each gem's info file is rebuilt from the lines of its allowed versions, keeping the
sha256 its source gave, and a `.gem` is refused unless it hashes to exactly that. A
gem with no listed checksum is refused too. Bundler reads the info of every
dependency of every version it weighs, so a gem with nothing allowed answers with an
empty version list rather than a refusal; only a download of an unapproved gem is
refused (451, which Bundler prints the reason for) and opens a request. `/versions`
lists the source's gem names so Bundler asks about each one. Gemspecs are passed on as
bytes and never read. `gem push` is not taken yet.

### Pushing gems

A publisher (or approver or admin) pushes to gem names an admin has reserved under
Settings → Registries → Reserved names, like `acme-*`. Put the token where the gem
client keeps its keys, and push to this source:

```bash
gem build acme-logger.gemspec
GEM_HOST_API_KEY=<token> gem push acme-logger-1.0.0.gem \
  --host https://npm.example.com/rubygems
```

- The name, version, platform, license, required Ruby version and runtime dependencies
  are read from the metadata inside the `.gem`, and become its line in the compact index.
- A pushed version never changes, pushing it again is a `409`, and `gem yank` is refused
  with a `405`.
- A new push is held until its malware scan is clean (or an admin releases it), and it
  goes through the checks in [What a publish may not carry](#what-a-publish-may-not-carry).
- `gem install` asks for a `.gemspec.rz` before it downloads a gem, and rubygems.org
  builds that at push time. So does this box: it is written from the gem's own metadata
  when the gem is pushed, and kept next to it.
- A reserved name is only ever answered from what was pushed here, never from
  rubygems.org, not even from a copy cached before it was reserved.

### CocoaPods CDNs

With **CocoaPods CDN** switched on, the box answers `/cocoapods/` as a CocoaPods CDN.
Add a CocoaPods registry (`https://cdn.cocoapods.org`), write rules, and point the
Podfile at it with `source 'https://npm.example.com/cocoapods/'`; pod reads the login
from `~/.netrc`.

The shards pod reads list only the allowed pods and versions. A podspec is handed out
with its `source` pointed at the box: the box fetches the pod's code itself, as the git
tag's archive from GitHub or GitLab or the http archive the podspec names, checks it
against any checksum the podspec gives, keeps and scans it, and serves that copy. A
source it cannot fetch as a fixed archive (a branch or commit, submodules, svn) is
refused with the reason, and a source on an internal address is never fetched. OSV has
no CocoaPods feed, so pods get no advisories; everything else applies.

### Swift package registry

With **Swift package registry** switched on, the box answers `/swift/` as a Swift
package registry (SE-0292). Add a Swift registry whose address is a git host
(`https://github.com`), write rules on identities like `apple.swift-log`, and point
SwiftPM at it with `swift package-registry set https://npm.example.com/swift/` and
`swift package-registry login`.

A package is a repository and its semver tags are its releases, read from git's own
ref listing rather than the host's API. The box fetches a tag's archive once, keeps and
scans it, reads `Package.swift` out of that copy, and hands SwiftPM the copy's checksum,
so a tag moved on the host later changes nothing. The release list holds only allowed
versions, and advisories come from OSV's SwiftURL feed. Publishing is not taken.

### Composer repositories

With **Composer repository** switched on, the box answers `/composer/` as a Composer
repository. Add a Composer registry (`https://repo.packagist.org`), write rules on names
like `monolog/monolog` or `symfony/*`, and point composer at it with
`composer config repositories.company composer https://npm.example.com/composer` and
`composer config repositories.packagist.org false`; the login goes in with
`composer config --global http-basic.npm.example.com <user> <token>`.

The metadata lists only allowed releases. Each release names one exact commit: the box
fetches that commit's zip once (from codeload.github.com for GitHub, so there is no API
rate limit), checks it against any shasum the metadata gives, keeps and scans it, and
points composer at the kept copy. The git source is taken out of every release, so
composer can not fall back to a clone. Branches are not served, and advisories come
from OSV's Packagist feed.

### RPM mirrors

With **RPM mirror** switched on, each RPM registry is one distro repository (the folder
that holds `repodata/`, like AlmaLinux 9 BaseOS), answered at `/rpm/<its name>/` for dnf
and yum. Pick its distro's advisory feed (AlmaLinux:9, Rocky Linux:9, Red Hat), and in
whitelist mode add an RPM allow rule of `*`, then deny or kill what you do not want.

By default the signed index goes out untouched, so clients keep `repo_gpgcheck=1`, and
every package download is checked: the rules, the kill switch, holds, advisories and
cooling off, then the package is checked against the checksum in the index, kept and
scanned. A mirror set to **Filtered index** hands out an index of only what the rules
allow instead, so dnf never picks a refused version; clients must then set
`repo_gpgcheck=0` (package signatures are still checked). Only the repodata and the
packages its index lists are served.

### APT mirrors

With **APT mirror** switched on, each APT registry is one Debian or Ubuntu archive
(`https://deb.debian.org/debian`), answered at `/apt/<its name>/` for apt. Pick its
distro's advisory feed (Debian:12, Ubuntu:24.04:LTS), and in whitelist mode add an APT
allow rule of `*`, then deny or kill what you do not want.

By default each suite's InRelease goes out untouched, so apt keeps checking the distro's
signature, and every package download is checked: the rules, the kill switch, holds,
advisories and cooling off, then the .deb is checked against its SHA256, kept and
scanned. A mirror set to **Filtered index** checks the distro's signature itself and
hands out Packages files of only what the rules allow (amd64 and arm64), signed with
the box's own key, which clients fetch from `/apt/signing-key.asc` and name with
`signed-by`. Advisories come from OSV by source package.

### Keeping cached files in a bucket

**Settings → Storage** can keep the blob store in a bucket instead of on this box:
AWS S3, or anything that speaks S3, such as MinIO, Cloudflare R2 or Wasabi. Requests
are signed on the box with the bucket's keys; no cloud SDK is installed.

1. Create the bucket, and a key that can read, write, list and delete in it.
2. Fill in the endpoint, region, bucket, an optional folder, and the keys. MinIO and
   most self hosted stores want **Path style addresses** on.
3. **Save and test the bucket** puts a small file in, reads it back and deletes it.
4. Set **Keep cached files in** to `s3` and save. The switch tests the bucket again,
   and changes nothing if that fails.

New files still land on this box's disk first, so a download never waits on the
bucket, and the uploader sends them up every minute. Every upload carries the file's
SHA-256 and the bucket refuses bytes that don't match it. Only once the bucket holds
a file whole is the local copy just a cache. A box that already has a cache uploads
all of it the same way; **What is where** on the Storage tab shows how far it has
got, and lists anything that keeps failing with its error.

**Local copies to keep** caps the disk. Once copies of files the bucket holds add up
to more than that, the least recently used are dropped, along with their old
`cache/tarballs` and `cache/pypi` links. A file the bucket doesn't hold yet is never
dropped, however full the disk gets. A file that isn't on disk is fetched back from
the bucket and checked against its SHA-256 before any of it is served, then kept as a
local copy again.

If the bucket can't be reached, installs carry on from the local copies and new
downloads wait on disk until it is back.

**Azure Blob** works the same way: pick `azure`, fill in the storage account, the
container, an optional folder and the account key, and leave the endpoint empty for
`https://<account>.blob.core.windows.net`. Requests are signed with the account key
(Shared Key), and every upload carries its MD5, which Azure checks and refuses the
upload if the bytes don't match; files fetched back are still checked against their
SHA-256. `AZURE_STORAGE_KEY` in the environment wins over the Settings field. **Save
and test the bucket** tests whichever of s3 or azure is picked, before switching.

The keys can come from the environment instead, which keeps them out of the
database: `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY` win over the Settings fields.
A plain `http` endpoint is refused unless the host is on a private network.

Once files are in a bucket, its endpoint, name and folder can't change, and the box
can't switch back to local disk, or to the other kind of bucket, on its own, because some files may only be in the
bucket. Emptying the whole cache also empties the bucket folder, after which both are
allowed again.

### Integrity alerts

npm and PyPI both promise that a published file never changes. When a registry
breaks that promise for something this box already holds, it shows up under
**Registry → Integrity alerts**, in the audit trail (`integrity.violation`), as a
count on the Dashboard, and in the hourly email digest for admins. Two kinds:

- **Published digest changed.** A fresh npm packument lists a different `sha512`
  integrity for a version we cached, or a PyPI project page lists a different
  `sha256` for a file we cached. Caught when the metadata is fetched, nothing has
  to be downloaded.
- **Downloaded bytes changed.** The file was downloaded again (say the cached copy
  went missing) and hashed to something else. The new bytes are kept aside for
  review. If the original is still on disk it keeps being served, otherwise the
  download is refused with a `502` until someone decides.

Nothing is swapped on its own. An admin either **keeps the original**, which closes
the alert and throws the held bytes away, or **accepts** the change: for new bytes
they become the served copy, for a changed published digest the cached copy is
dropped so the new file downloads on the next install. Either way the decision and
the optional note land in the audit trail. The same change seen again only bumps
the alert's count.

A package routed to a different registry is not an alert, that is a different file
with the same name.

### Quarantine

Quarantine holds back one exact file (a version's tarball, or a single PyPI wheel
or sdist) until an admin decides. Files get there two ways: every integrity alert
puts its file on hold until the alert is settled, and an admin can **Hold** any file
from its detail on the Artifacts page, with a reason. Everything held is listed
under **Registry → Quarantine**.

How a held file is treated depends on **Settings → Policy → Quarantine**:

- **permissive** (the default) still serves it. npm prints a `QUARANTINE` notice
  during the install, and the traffic log records it.
- **strict** refuses it with a `403` and leaves it out of the npm packument and the
  PyPI project page and JSON API, so a client resolving a range picks something
  else instead of failing on it. A hold on a wheel covers its `.metadata` file too.

An admin then either **releases** the hold, and the file is served normally, or
**rejects** it, and the file is refused and hidden in both modes until someone
releases it. Holds belong to the file, not to the cached copy, so purging a held
file and letting it download again does not get around them. Settling an
integrity alert only lifts the hold that alert placed; a manual hold on the same
file stays. Holds, releases and rejects all go in the audit trail. Approvers and
viewers can see the list; only admins can hold, release or reject.

### Safe version resolution

npm and pip pick a version themselves, from the metadata this box hands them. The
rules and quarantine already trim that metadata, so a client asking for
`lodash@^4.17.0` or `requests>=2.30,<3` picks the newest version inside its own
range that is actually allowed, and never sees the blocked ones.

**Settings → Policy → Safe version resolution** adds the security policy to that.
With it on, any version with a known advisory at or above the chosen severity
(`HIGH` by default) is also left out of the npm packument and the PyPI project page
and JSON API, and refused with a `403` when something asks for it directly, the way
a lockfile does. The client then picks normally from what is left. Nothing outside
the range the developer asked for is ever swapped in: if every version in the
range is excluded, the install fails and says so, rather than quietly getting
something else.

Two more reasons count, whatever the severity label says (an unrated advisory
included):

- **Also leave out what is exploited in the wild** (on by default): an advisory whose
  CVE is in CISA's Known Exploited Vulnerabilities catalog.
- **Also leave out likely exploits, EPSS from** (empty, so off, by default): an
  advisory whose CVE has at least this EPSS score, written `0.1` or `10%`.

Both read the CISA KEV and FIRST EPSS feeds below, so they need those on. The reason
a client is refused with names KEV or the EPSS score, and the check page says the same.

While it is on, every metadata answer that left something out is logged under
**Activity → Resolutions**: the package, the application and environment of the
token, how many versions were offered, each excluded version grouped by reason
(blocked by a rule, held in quarantine, or which advisory), and the version the
client then downloaded. The range the developer typed is not recorded, because
npm and pip never send it. The log follows the traffic log's retention.

### Provenance

Every cached file gets a provenance status, the same four for npm and PyPI:

- **verified**: a Sigstore attestation checks out and names these exact bytes. For npm
  that is the SLSA build provenance `npm publish --provenance` attaches, for PyPI the
  PEP 740 attestation a trusted publisher uploads.
- **unverified**: provenance is advertised but could not be checked, for example it is
  hosted somewhere other than the registry or the registry does not have it. Asked
  again daily.
- **none**: the release was published without provenance.
- **INVALID**: provenance is published but does not hold up. The signature fails, it
  names different bytes, it disagrees with its signing certificate, or (on PyPI) the
  certificate does not belong to the trusted publisher PyPI names.

Verification uses only Node's own crypto against a Sigstore trusted root pinned in
`app/src/trust/sigstore-trusted-root.json`, never keys the registry hands over: the
Fulcio certificate chain, the signing time inside the certificate's lifetime (taken from
Rekor's signed entry timestamp), the DSSE signature, the Rekor log entry naming this
exact signature, certificate and statement, and the statement's subject digest matching
the cached file. npm registry signatures are checked against keys pinned in
`app/src/trust/npm-registry-keys.json`. Refresh both files from Sigstore's TUF root and
`https://registry.npmjs.org/-/npm/v1/keys` when they rotate.

A verified file shows where it was built: repository, commit, ref, workflow, builder and
identity issuer, plus the attestation itself on the artifact page. Attestations are only
fetched from the same registry the file came from. **When provenance is INVALID**
(Settings → Policy) is warn by default, which records it and sends a `policy.violation`
event; hold also puts the file in quarantine. **Check provenance** on an artifact asks
straight away, otherwise a background check picks up new files within a few minutes.

**When provenance goes backward** (Settings → Policy, `hold` by default) watches for the
usual shape of a stolen publishing token: a new version with **no** provenance when an
older version of the same package came with verified provenance, or with verified
provenance built from a **different source repository** than the older versions. Only
older versions count, so an old release from before a project took up provenance is not
flagged. The file gets a `downgrade` hold (refused in strict quarantine, served with a
warning in permissive, the same as any hold) and a `policy.violation` event with severity
HIGH; `warn` sends only the event. Images are covered by trust policies instead, see
[Image signatures](#image-signatures).

### Install-time code and manifest confusion

The same background pass reads each new release against the one before it:

- **When a release starts running code at install** (`warn` by default, or `hold` or
  `off`): an npm version whose tarball has a `preinstall`, `install` or `postinstall`
  script, or a `binding.gyp`, when the version before it had none; a PyPI release that
  ships no wheel when the one before it had wheels, so installing it runs `setup.py`.
  Plenty of packages add a build step for good reasons, so this warns (a `policy.violation`
  event, severity MEDIUM, and a log line) unless you make it hold.
- **When an npm listing disagrees with its tarball** (`hold` by default): npm installs
  from the tarball's own `package.json`, so a registry listing that leaves out an install
  script or a dependency hides it from anyone who only reads the listing. A different
  name, version, install script, `dependencies` or `optionalDependencies` gets a
  `manifest` hold and a HIGH event; a different license, `bin` or `peerDependencies`
  only warns. The `node-gyp rebuild` npm writes into listings for a `binding.gyp` is not
  counted. Packages published here are not compared, their listing is built from the
  tarball.

**When a release looks like a takeover** (`warn` by default, or `hold` or `off`) records
what changed around a release, from metadata this box already holds:

- it was published by somebody who had not published that package before (npm records who
  published each version);
- a maintainer joined, or one is no longer listed, with that release;
- nothing was published for a year or more before it (npm and PyPI both date their
  releases).

Each of those happens for good reasons every day, which is why this warns rather than
holds: a `policy.violation` event with severity MEDIUM, a log line, and the reason on the
Quarantine hold if you do set it to hold. A first release has nothing to compare against
and is never flagged. Whether a maintainer's email domain has expired is not checked;
that needs a lookup outside the box.

Holds from any of these are ordinary holds: refused in strict quarantine, served with a
warning in permissive, released on **Quarantine**.

### Integrations

**Integrations** (Configuration) sends security events as they happen to a generic
webhook, Splunk HEC, or syslog over UDP, TCP or TLS as JSON or CEF. Each integration
picks the events it wants: `package.requested`, `package.cached`, `package.blocked`,
`package.quarantined`, `package.approved`, `package.released`,
`artifact.integrity_changed`, `vulnerability.discovered`, `vulnerability.remediated`,
`malware.detected`, `policy.violation` (served in audit only mode that the policy would
have refused), `waiver.created` and `waiver.expired`.

Every event is JSON with `id`, `timestamp`, `event_type`, `severity`, `ecosystem`,
`package`, `version`, `filename`, `artifact_hash`, `user`, `token` (the token's name),
`application`, `environment`, `source_ip`, `policy`, `reason`, `action`, `cve`,
`advisories`, `cvss`, `epss` and `cisa_kev` (null until the vulnerability feed carries
them). Passwords, token values, signing keys and HEC tokens are never included.

Events are queued and delivered by a background worker with retries that back off to
an hour, giving up after 10 tries. A SIEM that is down never slows an install, and
repeats of the same blocked install are sent at most once a minute. **deliveries** shows
the latest events per integration, and **Retry** requeues the ones that gave up.

Webhooks and Splunk HEC need https. A webhook with a secret signs each request:
`x-forgerepo-signature: sha256=<HMAC-SHA256 of "timestamp.body">` with the timestamp in
`x-forgerepo-timestamp`, so a receiver can check it came from here and reject replays.
Addresses on the box itself and cloud metadata addresses are refused, checked again on
every send, and webhooks never follow redirects. Secrets can be replaced or removed but
are never shown again, and changing an address requires sending the secret again.

### Consumers

**Consumers** answers "who has this?" for a package, a version or range, a file by
its sha256, or an advisory (CVE, GHSA or PYSEC id). It lists the applications and
environments that took it (production flagged), the developers and CI pipelines, the
addresses, how many downloads, and the first and last download of each.

Every download that was actually served is folded into one small row per version per
consumer, filled in from the traffic log on upgrade. It is kept for **Days to remember
who consumed what** (Settings → Cache, a year by default, 0 keeps it
forever), much longer than the raw traffic log. A consumer seen again is kept. An
advisory search finds the versions the vulnerability scan has matched to it, so run a
scan if the advisory is newer than the last one.

### Dry run

**Dry run** shows what a change would break before anyone switches it on. Pick a new
rule (allow or deny, with versions and an application or environment), a vulnerability
threshold for safe version resolution, or different license lists, and the last 1 to 90
days of downloads are replayed against it. The answer counts the packages, versions,
applications, applications in production, developers, CI pipelines and downloads that
would have been refused (or, for an allow rule, let through), with a table of each.

Nothing is saved and nothing is enforced. Production means an environment ticked as
production in Settings, Applications. A download counts as a CI pipeline when the client says so in its user
agent (npm adds `ci/github-actions` and the like, pip adds `"ci":true`), which is a hint
rather than proof. Existing waivers are taken into account, license changes only count
files whose license has been read, and a download already held today is not counted as
something the change breaks. Dry runs need the traffic permission.

### Waivers

A waiver is a written down, time boxed "yes, we know" for one finding on one package.
The **Waivers** page takes three kinds:

- **A known advisory**: serve a version that safe version resolution would otherwise
  leave out. The waiver names the advisory ids (**Look them up** fills them in). A version
  only counts as waived while every advisory on it is named, so a new advisory
  published later is never covered by an old waiver.
- **A license**: stop license enforcement holding that exact license on those
  versions. If the package changes license the waiver does not follow. License
  waivers cover everyone, since a license hold is on the file itself.
- **Cooling off**: serve versions still inside the cooling off period.

Advisory and cooling off waivers can be limited to an application or environment,
the same way rules can, so a waiver for dev never opens production.

Developers can ask for a waiver with a reason, and optionally a ticket or reference (a
change number, an issue key or a link), which stays on the waiver, in the lists, the
daily email and the audit trail. It is kept as plain text and never made clickable.
Approvers and admins approve, reject
or revoke them, or grant one straight away (recorded against their name). Every
waiver expires, at most **Longest waiver, in days** (Settings → Policy, 90 by default)
after it is granted, and then the finding applies again on its own, license holds
included. Approvers get a daily email about waivers waiting for a decision and ones
running out within a week, **Check a package → Show every version** says when a
version is only offered because of a waiver, and every request, decision, revoke and
expiry is in the audit trail. The kill switch, malware verdicts and integrity alerts
can never be waived.

### Kill switch

For the morning a package turns out to be compromised. **Kill switch** (top of the
menu) takes a package, or just some of its versions, away from everyone at once.

- Name the package, optionally the versions (`3.3.6`, `>=2.0.0 <2.3.1`, or empty for
  every version), and say why. Approvers and admins can do it.
- Or kill **one file, by its sha256**: those exact bytes are refused under whatever
  name and registry they turn up with, including a copy that only arrives later. For
  npm that takes the version the tarball is; for PyPI only that file (and its
  `.metadata`), the other files of the release still install.
- Or kill **an advisory** (`CVE-2021-44228`, `GHSA-...`, `PYSEC-...`): every version the
  vulnerability scan has recorded against it goes, under any of its names, since a GHSA
  and its PYSEC twin are one bug. A version the scan matches later is covered from
  then on, so run a scan straight after killing a brand new advisory. The page shows
  what each hash or advisory kill reaches right now.
- A kill beats everything: allow rules, pinned versions, application and environment
  scopes, cooling off exemptions, dismissed findings and audit only mode. Killed
  versions are left out of npm and PyPI metadata (and search, and dist-tags), and a
  lockfile asking for one by name gets a `403` carrying your reason. Caching a rule
  never pulls a killed version back in.
- **Also delete the cached copies now** removes the files straight away, for anyone
  allowed to purge the cache.
- Admins get an email the moment it happens, listing who pulled the package in the
  last 30 days, and **who pulled it** on the page shows the same from the traffic log:
  version, token, application, environment and address. For a range kill only
  downloads that named an exact version are counted.
- **Lift** puts things back to what the rules say. Kills and lifts are in the audit
  trail with who and why, and lifted kills stay listed.

### Lockdown and degraded mode

For the week an ecosystem is on fire (a worm spreading through npm, a registry
compromise), **Registry mode** at the top of the Dashboard changes what this box
fetches:

- **normal**: as usual.
- **degraded**: nothing new is fetched by name. Packages this registry already
  holds keep refreshing and installing, new versions of them included, but a
  package it has never fetched gets a `503` naming the mode, search is off and a
  cache warm will not start.
- **lockdown**: nothing is fetched from upstream at all. npm and PyPI metadata only
  offer versions and files already cached, so ranges settle on something that can
  be served, and anything else is a `503` naming the mode. Every other check still
  runs, and a file with any quarantine hold is refused even in permissive mode.

Approvers and admins can raise the mode the moment an incident lands; only admins
bring it back down. Every change needs a reason, is in the audit trail as
`registry.mode`, is logged as an error, emails the admins, and shows as a badge in
the top bar on every page until it is back to normal. Saving Settings and
importing a config never change the mode.

### Cooling off new versions

Hijacked and malicious releases usually get noticed and pulled within a few days of
going up. **Cooling off, in hours** (Settings → Policy) keeps brand new versions away
from your builds for that long. 72 is a sensible start; 0 switches it off.

- A version published less than that long ago is left out of npm and PyPI metadata,
  so a range like `^1.2.0` or `>=1.2` quietly settles on the newest version that is
  old enough. `latest` moves back with it.
- Asking for the version by name, as a lockfile does, gets a `403` saying when it
  will be served.
- The publish time comes from the registry: npm's `time` field, and for PyPI the
  first upload of the release, from the index page or the JSON API when the page
  has none. A late wheel added to an old release does not make it young again.
- **Never cooled off** takes package names or patterns with `*`, like
  `@yourcompany/*`, for builds you publish yourself.
- **A version with no publish time** decides what happens when a private registry
  gives no times: `allow` (the default) serves them, `hold` keeps them back.
- An allow rule pinned to that exact version skips the wait, since somebody has
  already looked at it. Audit only mode ignores cooling off.

Answers that left a version out for being too new are logged under **Resolutions**,
and **Check a package → Show every version** marks those versions as `cooling`.

### Typosquatting

A typosquat is a package whose name imitates one everyone uses: `lodahs` for
`lodash`, `reqeusts` for `requests`, `python-numpy` for `numpy`. Somebody publishes
it and waits for a typo in a `package.json` or `requirements.txt`. Every package name
asked for is compared against well known npm and PyPI names that are built in, the
names under **Also protect these names**, exact allow rules, and the packages this
registry serves most. It catches:

- a letter or two out, and two letters swapped
- separators moved or dropped (`lo-dash`, `pythondateutil`)
- look-alike characters (`l0dash`, `djang0`)
- extra words bolted on (`lodash-js`, `node-express`, `python-numpy`)
- a scoped name flattened (`babel-preset-env` for `@babel/preset-env`)

A name that is itself well known, is pinned by an exact allow rule, is on the
protected or **Never flag these** lists, or was marked "not a typosquat" is never
flagged. A package this registry serves a lot is protected from imitation, but
being popular here never makes a lookalike legitimate.

**Typosquat checks** (Settings → Policy) is `warn` by default: the package is still
served, npm prints a `TYPOSQUAT:` notice during install, and it is listed under
**Lookalike packages**. `block` refuses it with a `403` naming what it looks like,
and the blocked install opens a request carrying that reason. Audit only mode only
ever warns. Approvers can mark a finding "not a typosquat", and the first detection
of each name is written to the audit trail. **Check a package** warns about a
lookalike name too.

### Malware scanning

Every cached file can be run past one or more scanners. They all answer in the same
shape (scanner, scanner version, `CLEAN` / `SUSPICIOUS` / `MALICIOUS` / `ERROR` /
`NOT_SCANNED`, findings, signature, scan time), so the policy never cares which
scanner said it. Results are kept per SHA-256, so identical bytes under two names
are scanned once. Four scanners ship; pick them under **Settings → Malware**:

- **Hash blocklist**: SHA-256 values you already know are bad, one per line, with
  `#` notes.
- **ClamAV**: talks to a `clamd` over its INSTREAM protocol. The compose file has
  one ready to go: put `COMPOSE_PROFILES=clamav` in `.env`, run
  `docker compose up -d`, and set the clamd host to `clamav`, port `3310`. Its
  first start downloads the signatures, which takes a few minutes and needs
  internet; wait for `docker ps` to show it healthy before adding `clamav` to the
  scanners, especially with scan before serving on. It publishes no port, since
  clamd has no authentication. It holds about 1GB of memory, briefly double that while
  it loads new signatures.
- **REST scanner**: shown under Scanner status once a URL is set. It POSTs the file to that URL, with `x-forgerepo-sha256`,
  `x-forgerepo-filename` and an optional bearer token, and expects JSON back:
  `{"status": "...", "signature": "...", "findings": [...], "scanner_version": "..."}`.
  Redirects are refused and the answer is capped at 1MB.
- **Known-malicious packages (`osv`)**: asks osv.dev whether the exact package
  and version is in the OpenSSF malicious packages feed (advisories named `MAL-`).
  A hit is `MALICIOUS`. Only names and versions leave the box, never the file, and
  every name the same bytes are kept under is asked about. It knows only what has
  been reported, so it sits next to a content scanner rather than replacing one. On
  by default for new boxes, and added to a box still on the old default scanner list.
  If osv.dev can't be reached the result is `ERROR`, never a quiet clean.

A `MAL-` advisory published after a version was cached is caught by the scheduled
vulnerability scan. With **Kill known-malicious packages by themselves** on (the
default), that advisory goes on the kill switch as soon as it is recorded and admins
get the kill switch mail. It is added once: an admin who lifts it keeps it lifted.

YARA, VirusTotal or a sandbox would each be another adapter with the same two
functions; nothing else changes.

What a verdict does:

- **MALICIOUS** rejects the file through quarantine by default, so it is refused in
  both quarantine modes until an admin releases it. It can be set to hold or only warn.
- **SUSPICIOUS** holds it by default, so strict mode refuses it and permissive mode
  serves it with a warning. It can be set to warn or ignore.
- A file that later rescans clean has malware's open holds lifted. A rejection
  stays until a person releases it.

New files are scanned in the background as they are cached, so by default the very
first download of a brand new file can go out before its scan finishes.
**Scan before serving** closes that gap: a file with no answer yet is scanned on the
spot, and refused with a `503` if the scan takes more than a minute. A file whose exact
bytes already scanned clean with every content scanner that's on (ClamAV, the REST
scanner, secrets), with nothing ever flagging them, is served straight away; a
name-only scanner added since fills in its answer in the background.

If ClamAV is down, files it already passed keep being served, and a file it has not
seen yet is held with a `503` rather than going out unscanned. Clients retry, and
every 30 seconds the app checks whether clamd answers again; once it does, everything
that waited is scanned and goes out. Files are kept on disk while scan before serving
is on, even with **Keep tarballs on disk** off, since a file that isn't kept can't
be held. `setup.sh` also installs a small systemd timer on the host,
`forgerepo-clamav-watchdog@clamav.timer`, that restarts the ClamAV container when its
healthcheck says it has stopped answering, at most once every ten minutes
(`journalctl -t forgerepo-clamav-watchdog`). It is installed when ClamAV is in use;
turn ClamAV on later and `./setup.sh --upgrade` adds it. The Malware tab
also rescans whatever has not been scanned, or everything, and each artifact's detail
has **Scan now**. Detections land in the audit trail as `malware.detected`, and the
Dashboard counts flagged files. Scanning is off until you switch it on.

With email set up, **Settings → Email** has two switches for this, both on by
default. **Email admins when malware is found** sends every admin with an email
address a message within a minute of a new MALICIOUS or SUSPICIOUS verdict; several
detections close together share one mail, and a rescan of something already flagged
does not mail again. **Daily malware digest** sends admins, once a day, the list of
files still held or rejected by a malware scan, and nothing on a day with nothing
flagged.

**Check a package** has a **Show every version** button that lists each
published version as approved, blocked, quarantined or excluded, with the reasons,
so you can see what a client would be offered before anyone installs.

### Licenses

Each cached file has its license read from the package metadata: `license` (or the
old `licenses` array) for npm, and `License-Expression`, then `License`, then the
trove classifiers for PyPI, through the JSON API. It is turned into an SPDX
expression where it can be, so `GPL-2.0+` becomes `GPL-2.0-or-later` and
"Apache Software License" becomes `Apache-2.0`. Nothing is guessed: `SEE LICENSE IN`,
a pasted license text or an index with no JSON API counts as unknown, with a note
saying why.

**Settings → Licenses** has three lists, allowed, needs review and blocked, one SPDX
id per line with `*` as a wildcard (`BSD-*`). A license on more than one list gets the
strictest. In `MIT OR GPL-3.0-only` the better choice counts; in
`MIT AND GPL-3.0-only` the worse part does. Two more settings decide what a license
on no list is, and what an unreadable one is; both default to review.

What happens is up to **What to do about it**:

- **off** (the default) does nothing.
- **warn** logs it, and npm prints a `LICENSE:` notice during install.
- **enforce** holds review licenses in quarantine and rejects blocked ones, so they
  show on the Quarantine page and follow the quarantine mode. If the metadata cannot
  be read right then, the download gets a `503` instead of a hold made from a
  hiccup. In audit only (learning) mode, enforce acts like warn.

Changing a list re-judges every stored license straight away, with no network: a
license moved to allowed has its holds lifted, and one moved to blocked is rejected.
A hold a person released or rejected is left alone. Turning enforcement off lifts
the holds licenses placed. Files cached before licenses were switched on are read in
the background. The tab lists the licenses in use, and has **Read them all again**.
Artifacts show each file's license and can be filtered by verdict, and
**Check a package** shows the license and what the lists make of it.

### Cache housekeeping

The database records what is cached, the disk actually holds it, and the two
drift apart. A restore that brings the database back further than the disk, a
copy that stopped halfway, a full disk, somebody clearing space by hand. None of
it shows up in the portal, because every count on every page comes from the
database.

Serving copes with this on its own. A missing file falls through and gets
fetched again. The problem is the kill switch: with the upstream off there is
nothing to fall through to, and a row pointing at a file that is not there turns
into a `503` in the middle of somebody's build. So it pays to find out while the
upstream is still on.

Three buttons on the Packages page, under **Cache housekeeping**:

All three cover npm tarballs and PyPI files alike.

- **Check for drift** reads and reports, changing nothing. Rows whose file has
  gone, rows whose file is the wrong size, files nobody has a row for, and
  versions still cached that the rules now block. A missing file that is still
  in the blob store is called out, since it can be put back without a download.
- **Recache missing** puts the missing ones back and clears out the orphaned
  files. Files still in the blob store are relinked on the spot, which works with
  the upstream switched off; the rest are downloaded again. Anything the rules no
  longer allow gets dropped rather than fetched, since downloading something we
  would refuse to serve is just wasted bandwidth.
- **Purge blocked** removes cached files the rules now block, plus the cached
  metadata for packages left with nothing on disk. They can never be served, so
  they are pure disk cost, and a box that exists to keep bad versions out should
  not be sitting on a pile of them.

The checking part is thousands of `stat` calls, which take about a second for a
cache of this size. Nothing is downloaded until that has narrowed the work down
to the entries that are really broken, so a run on a healthy cache costs almost
nothing.

## Utilization

**Activity → Utilization** shows how hard the box is working, for admins:

- **Live gauges** for CPU, memory and the disk that holds `/data`, plus current
  network traffic in and out, refreshed every few seconds. Each shows the whole
  server and ForgeRepo's own share (its CPU cores and memory, and how much of the
  disk is the package cache and how much the database).
- **Trends** for CPU, memory, storage and network, for Today, Week, Month, Year or
  any dates you pick. Hover or tap a chart for the exact figures at that moment.

Samples are taken every 5 seconds and stored as 1 minute averages, kept for two
days, which is what Today draws. Those are averaged again into 2 minute points kept
for a month, and 10 minute points kept for a year; anything older than a year is
deleted. Each chart reads the finest table that covers the range, so a year is a
small, quick query.

The host figures come from the kernel's own counters and ForgeRepo's from its
container, so nothing needs the Docker socket. Network covers ForgeRepo's traffic,
not the whole server's. On a box shared by several nodes, each keeps its own
history under `NODE_NAME` (the container name by default), so recreating the
container does not start a new one.

## Watching for new vulnerabilities

An allow list is a photograph. It is right the day somebody writes it and wrong
soon after, because advisories land against versions that were fine when they
were approved. Nothing in a registry notices that on its own.

The **Vulnerabilities** page rechecks every version the rules currently allow
against [osv.dev](https://osv.dev), which aggregates the GitHub advisory
database among others. It runs on a schedule, set by **Hours between scans** in
Settings, and 0 turns it off. A full pass over seven thousand versions takes
about twenty seconds, because the feed takes bulk queries.

Each finding carries the severity, the CVE numbers, what the flaw actually is,
and the version it was patched in. `first_seen` is what makes drift visible:
anything that turned up recently appeared after the last time somebody looked.

**It never blocks anything by itself.** Blocking a version breaks whoever
depends on it, and that is not a decision for a background job at three in the
morning. Each finding has a **block** button that writes the deny rule for you,
at priority 1000, with the advisory detail in the note so the reason survives
long after whoever clicked it has forgotten. There is also **ack**, for the ones
you have looked at and decided to live with.

**Export CSV** and **Export JSON** at the top of the list write out every finding
the filter matches, which is the file to hand somebody who has asked what is
outstanding. It is the whole filtered set rather than the page on screen, and
with the filters empty it is everything the box knows about.

Versions that are already denied are left out of the scan. They cannot reach
anybody, so reporting them would just be noise.

The scan covers every version the rules pin **and everything in the cache**.
Most allow rules are a bare package name with no version pinned, so without the
second half the scan would have very little to look at on a normally configured
box. A version already sitting on a build agent is the one worth knowing about.
A version pulled for the very first time is checked on its own as the tarball
goes out, so it does not have to wait for the next scheduled pass.

### Known exploited, and likely to be

Severity says how bad a flaw would be. Two outside feeds say whether anyone is
actually using it:

- **CISA KEV**, the US government's catalog of vulnerabilities known to be
  exploited in the wild, with the date federal agencies are told to have fixed
  them by and whether ransomware campaigns use them.
- **FIRST EPSS**, a daily score for how likely a CVE is to be exploited in the next
  thirty days, and how that ranks against every other CVE.

Both are fetched once a day by default (**Fetch CISA KEV and FIRST EPSS** and
**Hours between intel fetches** under Settings → Vuln scanning, which also shows
when each feed last came in and why it did not), only ever from their public
addresses, and EPSS is only asked about CVEs this box has findings or advisories
for. Findings show **KEV** and the EPSS score, the list and its export can be
narrowed to **Known exploited**, the dashboard's vulnerable card counts KEV
findings, and `vulnerability.discovered` events carry `epss` and `cisa_kev` when
they are known. A box with no way out shows both feeds as not reachable and
carries on. Neither feed blocks anything by itself; with safe version resolution on,
a KEV listing, or an EPSS score past the bar you set, leaves a version out.

### Telling developers

Three switches at the top of the Vulnerabilities page, all on by default. **None
of them can fail a build.**

**Answer npm audit.** npm posts the tree it just installed to the registry and
prints what comes back, so `npm install` ends with `1 critical severity
vulnerability` and `npm audit` prints the detail. The answer is built from the
findings on this page, so nothing about your project leaves the box. This used
to reply with an empty report, which npm prints as `found 0 vulnerabilities`:
a clean bill of health that nobody had checked, which is a worse answer than no
answer at all.

`npm install` still exits 0. Only `npm audit`, run on purpose, exits non-zero,
and `--audit-level` is how a team opts into that.

**Warn during the install.** Affected versions are marked in the metadata on the
way out and a notice header goes on the download, so npm prints the name, the
version and the severity as it installs:

```
npm warn deprecated ee-first@1.1.1: SECURITY: ee-first@1.1.1 has 1 known
advisory against it, worst is critical (CVE-2026-99999). Fixed in 1.1.2
```

A real deprecation message from the publisher is kept in front of ours, and the
cached copy of the metadata is never touched. The warning is added to the copy
on its way out.

**Record who downloaded what.** Every pull of a version with a known advisory
gets a row with the client address, the token behind it, and what was wrong with
it at the time. That last part matters: the finding itself is deleted the moment
the advisory is fixed or the version is repinned, and this survives it. The list
is at the bottom of the Vulnerabilities page, and it is kept as long as the audit
trail rather than as long as the traffic log.

An empty audit answer means those versions have not been checked, not that they
are clean. Worth remembering before treating it as a green light.

## More than one registry to pull from

Sometimes a package does not live on the public registry. A supplier hands you
packages from a registry of their own, or an internal team publishes to one, and
everything else carries on coming from npmjs.

npm can do that itself with a per scope line in `.npmrc`:

```
@acme:registry=https://registry.example.com
```

The trouble is that this sends the developer straight at the other registry and
around this box. No rules, no cache, no audit trail, and nothing for the kill
switch to switch off. Doing the routing here keeps all of it.

**Ext Registries** in the nav is the list. One row is the default and takes
everything nothing else claims. **Add registry** takes a name, an address, a
pattern like `@acme/*`, and a token if that registry wants one. Anything
matching the pattern comes from there and only from there. **remove** takes a row
back out; the default cannot be removed, only pointed somewhere else.

Each registry carries its own token, sent as a bearer credential to that
registry and nowhere else. Tokens are write only, like every other credential
here: the page shows whether one is set and never the value, leaving the stars
alone keeps the current one, and emptying the box clears it. They are never
included in an export.

Address, pattern and priority are editable in place. Change them and press
**save** on that row.

Patterns are matched the same way rules are (first match wins, an exact name
beats a glob, a longer glob beats a shorter one), so the order you added them in
never decides anything.

### Why it is patterns and not a fallback chain

The obvious design is to ask each registry in turn until one answers. That is
also exactly how dependency confusion works. Somebody publishes a package on the
public registry using a name your supplier uses, it answers first, and it wins.

With a pattern, `@acme/*` can only ever come from the registry written against
it. A near miss goes to the supplier, who says 404, and the install stops, which
is the right way around, because the other direction ends with a stranger's code
in your build.

The match is deliberately case insensitive for the same reason. `@ACME/thing`
routes to the supplier rather than escaping to the public registry.

There is a **falls back** switch per registry for anyone who really does want the
default asked as well on a 404. It is off unless you turn it on.

### What happens to what is already cached

Every cached document and tarball records which registry it came from. A copy
from a registry that no longer serves that name is not served: it gets fetched
again from wherever the name points now. So adding a supplier registry for a
scope you have already pulled from npmjs does the safe thing on its own, with
nothing to purge by hand.

If the upstream kill switch is off at that moment, the request gets a 503 saying
exactly that, rather than the copy from the old registry.

This holds for every type routed by name: npm, PyPI, NuGet, Maven, RubyGems, Composer,
CocoaPods and Swift. A copy published here always counts, and with **falls back** on,
so does a copy from the default registry. Images are different by design: a blob is
only ever served under the digest it hashes to, so where it came from does not change
what it is. RPM and APT mirrors are addressed by mirror, not routed by name.

Removing a registry works the same way. What it cached stays on disk and simply
stops being handed out.

Upgrading an existing box needs nothing. Whatever the single upstream setting
said becomes the default row on first boot, and everything already cached is
stamped as having come from it.

## The traffic page

Every request npm made, newest first, filterable by package and by what happened
to it. Show 100, 500 or 1000 rows a page, whichever suits what you are doing;
1000 is as far as the API will go in one answer.

Two of the columns are about versions and they are not the same thing.
**Version** is what was asked for, which only a tarball request has: npm asks for
a package's metadata without naming a version at all, then works out which one it
wants from the document it gets back. So metadata rows have always had that
column empty, and that is most of the log.

**Pulled version** is what actually came down the wire. On a tarball row it is
the version served. On a metadata row it is filled in afterward from the tarball
request that followed it, matched on the install session id npm sends with every
request in one install. One install can take more than one version of the same
package, and then all of them are listed.

If nothing was ever downloaded against a metadata request, there is no fact to
report and the column falls back to the latest version on offer, grayed out and
marked `(latest)`. Treat that as the guess it is. It is only right when nothing
constrained the choice, like an `npm install lodash` with no range and no lockfile.
Most metadata requests during an install are for a dependency with a range on it,
and npm takes the newest version that satisfies the range, which is often not the
newest that exists.

The usual reason a metadata request never leads to a download is npm's own cache:
on a repeat install it still re-checks the metadata here, but the tarball comes
off the developer's disk and never reaches this box. `npm view`, `npm ls` and
`npm audit` do the same.

Rows written before the upgrade that added this keep whatever they already knew:
old tarball rows show their version, old metadata rows stay blank, because there
is no session id on them to match anything up with and a guess after the fact is
worth nothing.

### Which application pulled it, and where

Every row also carries an **application** and an **environment**, and both can be
filtered on. They come from the token the request was made with.

You keep two lists under **Settings**, on the **Applications** tab: what your
applications are called, and what your environments are called. A developer
making a token picks one of each from those lists, and from then on every request
that token makes is stamped with both names.

This is what turns "a malicious version was pulled through here" into "it is in
the checkout api, in production, and it landed on the eleventh". Without it the
traffic log names an address and a token, and an address is a build agent that
has since been rebuilt.

The names are copied onto each row as it is written rather than looked up later,
and that is the whole point. Months afterward the token may have been revoked,
moved to another application, or deleted outright, and none of that is allowed to
change what the row says was true at the time. The same two columns are on the
**pulled with a known advisory** list at the bottom of the Vulnerabilities page,
which is the list somebody actually works through after an advisory lands.

Both are optional. A token made before these lists existed carries neither, and
its rows read `unassigned` rather than showing a blank, which would look like
nothing had happened. Filtering for `unassigned` is how you find the installs
nobody can attribute yet, and the fix is to set the two dropdowns on that token.

One token per application per environment is what makes any of this worth having.
A token shared between two applications can only ever name one of them, and it
will name it confidently on both applications' traffic.

Renaming an application follows every token pointing at it, because the token
holds the id rather than the text. It does not rewrite history: rows already
written keep the name that was true when they were written.

Removing one is a **retire**, not a delete. A retired entry stops being offered
for new tokens and stays on the ones already carrying it. An outright delete is
refused while any token still points at it, revoked ones included, because
dropping the row underneath a token would turn its label into `unassigned` and
that reads as though nobody ever set one.

## Import and export

The **Import / export** page will hand you your rules as JSON or CSV, and take
them back in either format. CSV needs a header row with at least `pattern` and
`kind`, and it understands `pattern, kind, version_range, note, priority, enabled`.

The Rules page has the same two buttons under its filters, and there they write
what the filter matched rather than everything: search, kind, cache state and
advisory state all carry into the file, and it is the whole filtered set, not the
page on screen. The columns are the same either way, so an export of the allowed
and vulnerable rules still imports straight back into another box.

The Vulnerabilities page exports the findings the same way, as JSON or CSV, with
the package, version, severity, CVE numbers, advisory ids, summary, patched
release, when it was first and last seen, and whether it has been acked. Leave
the filters empty and it is every finding on the box.

The Traffic page exports the same way again, and it is the rows the filter
matched rather than the page on screen, so a month of installs comes out in one
file. On top of the columns the page shows, the file carries the install session
id, which npm sets once per install and sends with every request in it, so the
metadata request and the tarballs it led to can be lined back up in a
spreadsheet. The whole log unfiltered is a large file on a busy box, so it is
worth narrowing down first.

Every line on the Traffic page has a **why** (or **details**) link that explains it
in one place: what happened, the reason given, who asked (account, token, address
and CI), the application and environment, the rule or check that decided it, and the
evidence this box holds, such as the file's sha256 and scans, quarantine holds,
integrity alerts, a known advisory, a lookalike match, a kill switch, how many
consumers already pulled that version, requests waiting on it and the rest of the
same install. It ends with what to do next. Refusals by cooling off, safe version
resolution, the license policy and the registry mode now record which check made
them, alongside the kill switch, lookalike, malware and quarantine ones.

Exporting is a read, so every role can do it, down to viewer. Import stays with
approver and admin, and a viewer sees only the export half of the page.

Import has two modes. `merge` keeps what is already there and updates anything
that matches, `replace` clears the rules first. There is a "try it first" button
that reports what would happen without touching anything.

Settings in a config import go through the same checks as saving the Settings
page, and are audited the same way, so a value the page would refuse is refused
here too and reported back. Credentials and the registry mode are never taken
from a file.

The whole config export adds the settings and both IP allow lists. Passwords,
tokens and break glass keys are never included in any export.

### Large lists

There is no limit on how many rules a file holds. An SBOM for a big estate can
run to tens of thousands and it goes in as one file.

Imports are written in batches inside a single transaction, so a large list is a
few hundred round trips rather than one per rule, and it either lands whole or
not at all. That last part is what `replace` mode depends on: a failure halfway
through cannot leave you with the old rules deleted and the new ones missing.

Exports stream row by row instead of building the whole file in memory first, so
the size of the list is not a problem at either end.

The one ceiling is how much text the API will take in one request, which is 64MB
by default. At roughly 200 bytes a rule that is room for about 300,000 of them.
Raise it with `MAX_IMPORT_MB` in `.env` if you need to; the server and the
browser both read the same number, so they cannot disagree about what fits.

## Settings worth knowing

The page is split into tabs: Policy, Registries, Cache, Storage, Vuln scanning,
Malware, Licenses, Email, SSO, Access and Applications. The client allow list lives on the
Whitelists page now. Everything on every tab is saved
by the one **Save settings** button at the bottom, whichever tab is on screen,
because the fields are all still on the page. The Applications tab is the
exception and says so: those are rows rather than settings, so adding, retiring
and deleting take effect as you do them.

**Registries** has the package types this box serves, which clients it answers,
and the upstream registries themselves. The registry rows are rows too, so they
save as you add, edit or remove them, the same as Applications. Links to the old
External registries page open this tab.

**Audit only** is learning mode. Everything is served, what would have been blocked
is logged, and anything pulled that no allow rule covers opens a request under
**Requests**, marked as coming from learning mode. Each request collects the exact
versions that were actually installed (`4.17.21 || 4.18.1` for npm, `==2.32.3` for
PyPI), so approving it writes an allow rule for precisely those versions and nothing
more. A package pulled again folds into its existing request instead of opening
another, and once it is approved, installs of those versions stop adding to the
queue. Learning mode opens requests even with automatic requests switched off, since
filling the queue is the point, and like blocked-install requests it ignores traffic
that does not look like npm, yarn, pnpm, bun or pip.

It works with either mode. With **whitelist** it learns everything not yet approved.
With **blacklist** it learns everything that is not explicitly allowed, while deny
rules are still logged as what would have been blocked. Run it for a week or two,
work through Requests to approve what your teams really use, then switch to whitelist
and turn Audit only off. Far less painful than turning a whitelist on cold.

**Seconds we will serve stale metadata** means a public npm outage does not stop
your builds. Anything already cached keeps being served.

**Upstream registry enabled** is the kill switch, and it covers every registry in
the list. A switch some of them ignored would not be worth having. Turn it off
and this box never calls out again. Anything already on disk is still served, at any age, and
anything else gets a `503` saying so. That is what you want on a day like the
keyv compromise: builds that only need copies you already hold keep running,
and nothing new comes in from a registry you no longer trust. Turn it back on
and normal fetching resumes.

The catch is that the switch only helps if the cache holds what you need, and an
allow rule on its own puts nothing on disk. That is what **Cache the ticked
rules** on the Rules page is for. Tick some allow rules, press it, and the
approved versions are downloaded now rather than the first time somebody asks.
It runs in the background and shows progress, so you can leave the page.

It works for npm and PyPI rules alike. For PyPI a release is every file of it,
each platform wheel plus the source archive (and their metadata files), because
there is no telling which one a machine will ask for. That makes a project like
numpy a big download per version, so pin what you actually use.

Limits worth knowing, all reported rather than silent. Only rules pinning exact
versions are cached (`4.17.21`, `==2.5.3`, or several joined with `||`); a range,
or no range at all, names no particular release and is skipped. One run stops at
2000 files, so just run it again to carry on. Wildcard patterns like `@acme/*`
are skipped, because expanding one would mean asking the registry for its whole
index.

The **Cache** column on the Rules page counts the exact versions a rule pins, not
just anything held under that package name, so it reads `2 of 5` rather than a
bare number. The difference matters: a rule repinned from `4.17.21` to `4.18.1`
is not cached because the old tarball is still on disk, and a column that said
otherwise is how you find out the hard way that the kill switch has nothing to
serve. The **not cached** filter uses the same test.

The **Advisories** column and the **vulnerable** / **not vulnerable** filter next
to it answer the other half of that question: of the versions this rule lets
through, how many does the last scan have a finding against, and how bad is the
worst of them. It is judged the same way the cache column is. A rule pinned to
exact versions is answered on those versions, so a rule repinned to `4.17.21` is
clean when the advisory is against `4.17.20`. A rule holding a real range like
`^4.0.0`, or no range at all, covers versions that cannot be listed from the rule
itself, so it falls back to whether the package name has any finding against it.
Wildcards read `n/a` and are in neither answer: there is no single name to look
up, and calling one clean would be a claim about packages nobody has checked.
**allow** plus **vulnerable** is the pairing worth keeping an eye on, which is
what the link under the filter selects.

**Tell blocked developers where the portal is** puts the portal address in the
error npm prints. Handy internally. Turn it off if the registry is reachable from
outside your network.

**Minutes to keep the dashboard numbers** is how long the front page holds on to
its counts. Working them out means counting a day of traffic and the size of the
whole metadata cache, which is not something worth waiting for on a page you open
twenty times a day, so it is done on a timer. Anything you change in the portal
drops the cached copy straight away; only npm traffic waits. There is a button on
the page to count again now, and 0 counts on every visit.

### The audit trail

**Audit trail** records every sign in attempt and every change made in the portal:
when, who (and who they were acting as), from which address, the action, what it was
done to, and whether it **worked**, **failed** or was **refused**.

Changes to settings, rules, upstream registries, users, integrations, whitelists,
tokens, requests, waivers, quarantine holds, integrity alerts, the kill switch and the
registry mode also record what the thing was **before** and **after**, and **before
and after** on a row shows the two side by side. Passwords, secrets, tokens, keys and
password hashes are never written: one that changed shows as stars. Saving Settings
records only the settings whose value actually changed.

A signed in user whose role does not allow something is recorded as `access.denied`
(once every few minutes for the same person and the same thing, so a stuck page does
not flood the trail), and so is a login refused for too many attempts from one
address, or refused by the SSO provider. The list filters by what the action starts
with, who did it and the result, and **Export CSV** and **Export JSON** write every
row the filter matches. Taking an export is itself on the trail.

### The dashboard

The first page in the portal. Seven cards sit at the top:

- **Vulnerable packages**: packages with a known advisory, how many versions that
  covers and how many of them are critical or high.
- **Malicious packages**: files a malware scanner flagged, blocked lookalike
  packages and active kill switches, and how many installs those checks refused in
  the last 24 hours.
- **License violations**: packages whose license is blocked, and how many more
  need a license review.
- **Risky packages in use**: vulnerable versions somebody actually pulled in the last
  30 days, how many applications pulled them and how many are on CISA KEV. Its list
  puts known exploited first, then the EPSS score, then severity and downloads,
  which is a sensible order to fix things in rather than a science.
- **Integrity alerts**: files whose bytes or published digest changed after this
  box first saw them, still waiting for someone to accept or dismiss them.
- **Waivers ending soon**: waivers that run out within the next 7 days, and the ones
  that ran out in the last 7, with their tickets, so nobody is surprised when a
  finding applies again.
- **Bandwidth**: what clients pulled and how much of that had to be fetched from an
  upstream registry first, for the last 24 hours and as a daily average over the
  whole days the traffic log still holds (90 at most). Pushed says "publishing is
  off" until the registry accepts publishes.

Clicking a card lists the packages behind it, up to 100, each marked npm or PyPI,
with a link to the page that has the rest. A card only opens for a role that can
see that page. A number turns red when something needs a look and amber when it is
worth a glance.

Below the cards, **Busiest applications this week** counts requests, distinct
packages and refusals per application and environment, from the token each request
used.

Refusals by a kill switch, a lookalike check, a malware verdict or a quarantine hold
are recorded with the check that made them, so the attempt counts come from that
rather than from reading the reason text.

### Your own name and icon

**Name shown in the portal** (Settings → Policy) is used in the header, on the sign
in page and as the browser tab title. The **Branding** box under it swaps the anvil
for your own **header icon** and **favicon**. Each saves as soon as you pick a file,
and **Use the default** puts the anvil back.

Uploads are PNG, JPEG, GIF or WebP, and the favicon can also be an ICO. They are
16 to 1024 pixels a side and 256KB at most. The type is read from the file's own
bytes, never from its name or what the browser says it is, and SVG is refused
because it can carry script. The images are kept in the database, so every node
serves the same ones, and they sit behind the same IP allow list as the portal.
Changes show up on other nodes within 30 seconds, and every upload and reset is in
the audit trail.

### What counts as a busy package

The busiest list counts **tarballs served**, not metadata requests. Anything on
the open internet gets scanned, and a scanner asking for `/index.php` looks
exactly like a metadata request for a package called `index.php`, which really
is published on npm, along with plenty of other names that look like a probe. No
pattern separates the two.

A tarball does. It has to be a valid version, the filename has to match the
package, and the file has to come off the disk or the upstream registry, which
no scanner ever gets to. A blocked tarball counts too, but it can only update a
package we have served before, never create one.

The same reasoning applies to requests: a blocked install only opens one when it
came from something that announces itself as a package manager. Both lists on the
dashboard have a **clear** link for an approver, which resets the counts without
touching the traffic log, the cache or the rules.

## Signing in with your identity provider

OpenID Connect, under **Single sign on** in Settings. Okta, Entra, Google,
Keycloak and the rest all speak it. SAML is not supported and is not planned:
it would mean verifying XML signatures, which is unforgiving to get right, and
every provider worth integrating with has spoken OIDC for years.

Register an application at the provider as a web application using the
authorization code flow, and give it the redirect address the Settings page
shows you, which is your public url with `/_api/sso/callback` on the end. It has
to match at both ends exactly. Then fill in the issuer, the client id and the
client secret here and press **Check the provider**: that reads the provider's
own configuration and tells you what came back, which is where a typo in the
issuer turns up. Do that before you turn anything on, and certainly before you
turn the password form off.

The flow is the authorization code one with PKCE. Nothing that arrives in the
browser is trusted: the code is swapped for an id token on a connection this box
makes itself, and the signature on that token is checked against the keys the
provider publishes before a word of it is believed. A login that is replayed
finds its state already spent. Keys that have been rotated are refetched once
before a token is called a fake.

People are matched to an account by email address first, and by login name after
that, so somebody's username changing at the provider does not strand them. With
**Make an account on first sign in** on, anybody the provider lets through gets
an account here as the role you pick. Admin is not on that list on purpose. An
account that already exists keeps the role it has, so promoting somebody is
still a decision made here.

### Both, or only SSO

**both** keeps the password form beside the button, which is the sensible place
to start. **sso_only** refuses a password login even with the right password.

That second one is worth being clear-eyed about: when the provider is down, or
the client secret expires, or somebody saves a typo in the issuer, that is
everybody locked out of the portal, including you, with no way back in through
the portal because getting into the portal is what is broken.

So there is a way back in from the server itself:

```bash
./enable_local_login.sh              # put the password form back
./enable_local_login.sh --status     # say how sign in is set up, change nothing
./enable_local_login.sh --off-sso    # the above, and switch sso off entirely
./enable_local_login.sh --admin tim  # also clear a lockout on that account
```

It writes the setting through the app's own code, so the change lands in the
audit trail like any other, and the running server picks it up within thirty
seconds. Nothing is restarted and nobody is logged out. Sign in, fix the
provider, and put the mode back to `sso_only` in Settings.

What it cannot do is invent an account with a password on it. An account made by
single sign on has no usable password by design. So make yourself a local admin
account, with a password, while sso is working, not after it stops. The script
tells you how many accounts there are and how many of them are admins, which is
the number that matters on the morning you need it.

The registry itself is not affected by any of this. npm clients authenticate
with tokens from the Tokens page, which is a separate thing entirely, so
installs and CI carry on regardless of what the provider is doing.

## Email and the digest

Off until you turn it on, and nothing anywhere sends a message while it is off.

Two ways out, both under **Email** in Settings. **smtp** is a relay on your
network: hostname, port, and starttls, tls or nothing. A username and password
are optional, because plenty of relays take anything from an internal address,
and if you do set one it will not be sent over a connection with no tls. That
is refused rather than quietly done. **graph** is Microsoft 365 through an app
registration, for a tenant that has smtp auth switched off: register an
application in Entra, give it the `Mail.Send` application permission, grant
admin consent, and fill in the tenant id, the application id, the client secret
and the mailbox to send as. Worth scoping that permission to the one mailbox
with an application access policy, or the registration can send as anybody in
the tenant.

**Send a test** saves what is on screen and sends one message straight away,
whether or not the switch is on, because checking the settings is what you want
to do before turning it on rather than after. Whatever the mail server said
comes back with it, so `550 5.7.1 relay denied` reads as itself and not as
"sending failed". Every attempt, including the ones that did not go, is on the
same page underneath.

### What goes out, and why you only get one

Nothing is emailed as it happens. A request is not an event anybody wants a
message about on its own: an approver clearing a backlog of thirty would put
thirty mails in one inbox, which is how a notification setting gets switched off
for good and how the one that mattered gets missed with the rest.

So it is a digest, hourly at the very most, and only to somebody with something
new to hear:

- **developers** hear what happened to the requests they opened, approved,
  turned down and blocked in one message
- **approvers** hear what has landed on the list since the last one

Every address carries a mark, the run asks what has happened since that mark,
and the mark only moves once the mail is actually away. So the same five
requests are never sent twice: five waiting means one message, the same five
still waiting next hour means nothing at all, and one more landing on top means
one message about the one, with the others as a count rather than a repeat of
the list. A mail server that was down all day means one catch up rather than a
day of backlog, and an address seen for the first time starts from now, so
switching this on does not post everybody a year of history.

Several nodes on one database all run this on the hour, so the run takes a lock
first and the ones that do not get it do nothing. Nobody gets a copy per node.

### Tokens can have their own address

A registry token can name a contact address, on the Tokens page, and it is worth
setting on a shared build token. A token belongs to whoever minted it, but a CI
runner is usually looked after by a team, so the digest about what that token
got blocked on goes to the address on the token rather than to the person who
happened to create it. Leave it empty and it goes to the account behind the
token, as it always did. The address can be changed later without reissuing the
token, which would otherwise mean editing an `.npmrc` somewhere.

## Running more than one node

By default the database lives inside the container on a unix socket, which is
the right answer for one box. Set `DB_HOST` in `.env` and it uses an outside
MySQL or MariaDB instead, and the local one is not started at all. That is what
lets two or more nodes share the same rules, users, requests and audit trail.

RDS, Cloud SQL or a server of your own all work. The schema builds itself on
first boot either way, so an empty database is all that is needed.

### Pointing at an outside database

Create the database and an account for it first:

```sql
CREATE DATABASE npmrepo CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'npmrepo'@'%' IDENTIFIED BY 'a long password';
GRANT ALL PRIVILEGES ON npmrepo.* TO 'npmrepo'@'%';
```

`ALL PRIVILEGES` on that one database, not just read and write. Every boot runs
`CREATE TABLE IF NOT EXISTS` and the migrations run `ALTER TABLE`, so the account
needs schema rights or the app will not start.

Then fill in the `DB_` block in `.env` and bring it up. Turn on `DB_SSL` for
anything reached over a network. `DB_SSL=rds` verifies against Amazon's CA
chain, which ships with the driver, so RDS needs no certificate file. MySQL 8
authenticates with `caching_sha2_password` and is happier encrypted, so turn it
on there whichever host it is.

The boot log says which one it picked, and it is worth reading:

```
database is npmrepo.abc123.eu-west-1.rds.amazonaws.com:3306/npmrepo over tls
database is the one in this container (/run/mysqld/mysqld.sock)
```

A node that was meant to join a shared database and quietly fell back to its own
looks like it is working right up until the two disagree about everything.

**How fast a change reaches the other nodes.** Each node keeps a little in memory and
checks the database for changes on a timer, so a decision made on one node takes effect
on the others within a few seconds:

| Changed | On the other nodes |
| --- | --- |
| A kill, a rule, a waiver, a lifecycle stage | within 5 seconds |
| A quarantine hold, rejection or release | at once, they are read per request |
| A revoked or changed token, a disabled user | at once, they are read per request |
| A setting: lockdown, degraded, require a token, quarantine mode, policy mode | within 5 seconds (a stamp on the settings table is polled; the node that made the change has it at once) |

Nothing is cached across a decision boundary for longer than that. There is no message
bus between nodes: everything goes through the database they share.

### Moving an existing box onto one

Run this while the container is still on its own database, before setting
`DB_HOST`:

```bash
docker exec npm-repo node /opt/npmrepo/src/migrate-db.js --check \
  --host db.example.com --user npmrepo --password 'secret' --ssl rds
```

`--check` connects, reports the server version, checks the account can create
and alter tables, checks the largest row fits inside the target's
`max_allowed_packet`, and refuses if the target already holds rows. It also
makes sure every table on this box is on the copy list, so nothing gets left
behind. It changes nothing. Run the same command with `--run` once it is clean.

Every table comes along: rules, users, tokens, artifacts, quarantine holds,
waivers, kill switches, integrations, provenance and the rest. The cached package
files themselves stay on this box's disk, only their rows move.

The local database is never touched, so backing the change out is a matter of
emptying `DB_HOST` and starting again. `--skip-packuments` leaves the cached npm
metadata behind, which is most of the size and refetches on demand.

### Adding a second node

```bash
sudo ./setup.sh --url https://npm.example.com \
  --db-host db.example.com --db-user npmrepo --db-password 'secret' --db-ssl rds
```

It skips the first admin account and the break glass key, because both already
exist in the shared database. Sign in with the account you have.

### What is shared and what is not

Shared, because it is all in the database: rules, users, sessions, tokens,
requests, both ip allow lists, settings, the audit trail, vulnerability findings,
and the *record* of which tarballs are cached.

**Not shared: the tarball files themselves.** Those live under `/data/cache` on
each node. That is usually fine, because a cache miss is fetched again, and the
path is a hash of the name and version so the same tarball always lands in the
same place. It matters in one case: with **the upstream switched off**, a node
can only serve what it has already pulled, and the shared database will happily
tell it that a version is cached when the file is on the other node. Run **Check
for drift** on the Packages page after any failover to see where each node
stands.

If you want the files in step, `rsync` or `unison` between the `/data/cache`
directories is safe. The tree is content addressed and a tarball is written once
and never changed, so two nodes can never disagree about the contents of a path.
Do not sync `/data/mysql`; that is the local database you are no longer using.

### Before you put a load balancer in front

Some things still assume one node, and are worth knowing:

- **Background jobs run on every node.** The vulnerability scan and the log
  cleanup schedule themselves per process, so two nodes will both run them.
  Harmless but wasteful, and the scans will race.
- **Job progress is held in memory.** Start a cache warm on one node and a
  progress poll that lands on the other reports nothing running, and Stop does
  nothing. The job still finishes.
- **Rate limits are per node.** The break glass throttle of five tries per
  address per fifteen minutes becomes five *per node*.
- **Settings take up to 30 seconds to reach another node**, rules and the
  policy cache up to 5.

None of that stops it working. It does mean an active-passive pair, with the
load balancer health checking and failing over, is a calmer arrangement than
active-active until those are addressed.

## The reverse proxy

`nginx/npm-repo.conf.example` is a complete working vhost. Change the hostname,
drop it in, get a certificate, reload.

Two details matter if you write your own instead, or swap nginx for something
else:

**Set `X-Forwarded-For` to the client address, do not append to it.** nginx
spells that `proxy_set_header X-Forwarded-For $remote_addr`. The usual
`$proxy_add_x_forwarded_for` tacks the real address onto whatever the client
sent, and since both ip lists read this header, that would let anyone claim
to be an approved address.

**`TRUST_PROXY` has to be at least 1.** Docker publishes the port, so the
connection reaches the app from the bridge gateway rather than from localhost.
Set it to 0 and every request looks like it came from `172.x.x.1`, which breaks
the whitelist and makes the logs useless.

**Give docker push room.** Each image layer arrives as one request body. The example
config keeps a small body limit for everything and gives `/v2/.../blobs/uploads/` up
to 10 GB, streamed straight through with request buffering off. Without that, a push of
anything bigger than the limit fails with `413 Request Entity Too Large`.

**Nothing but the proxy may reach the app's port.** A number in `TRUST_PROXY`
means the address in `X-Forwarded-For` is believed from any connection at all,
and both allow lists decide on that address. Anything that can reach
`HOST_BIND:HOST_PORT` without going through the proxy can send the header itself,
claim an allowed address, and be let into the portal. Either keep the port where
only the proxy can reach it, `127.0.0.1` when nginx is on the same box, or set
`TRUST_PROXY` to the address the proxy's connections arrive from, so the header
is believed from nowhere else. The app says so in its log at start up while
`TRUST_PROXY` is a number.

## Poking around

```bash
# logs
docker compose logs -f

# the database
docker exec -it npm-repo mariadb npmrepo

# what got blocked today
docker exec npm-repo mariadb -B npmrepo -e \
  "SELECT ts, ip, package_name, reason FROM access_log WHERE action='deny' ORDER BY id DESC LIMIT 20;"

# how big the cache is
du -sh data/cache
```

## Things it does not do

- Deleting what was published. `npm unpublish` and a registry `DELETE` are refused,
  a published version or pushed image is kept for good.
- Mounting a layer from another repository during `docker push`. docker uploads the
  layer again instead, so one repository's layers are never reached through another.
- Sending your dependency list anywhere. `npm audit` is answered from what this box
  already knows about the packages it serves.
