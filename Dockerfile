# pinned by digest. newer ubuntu? pull it, scan it, update BOTH FROM lines

# node from nodejs.org (ubuntu's lags on security fixes). sums are from a signature
# checked SHASUMS256.txt, bump all three ARGs together
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d AS node
ARG NODE_VERSION=22.23.2
ARG NODE_SHA256_X64=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307
ARG NODE_SHA256_ARM64=fff4078c5def658577f92c88db7db3bc0072924bfb93fe52c1e744a54e94abb8
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && case "${TARGETARCH:-amd64}" in \
         amd64) arch=x64; sum="$NODE_SHA256_X64" ;; \
         arm64) arch=arm64; sum="$NODE_SHA256_ARM64" ;; \
         *) echo "no node checksum is pinned for ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
    && echo "${sum}  /tmp/node.tar.xz" | sha256sum -c - \
    && mkdir -p /opt/node \
    && tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 --no-same-owner \
    && rm /tmp/node.tar.xz

#lockfile + npm ci = same deps every build. npm itself stays in this stage
FROM node AS deps
ENV PATH=/opt/node/bin:$PATH
WORKDIR /opt/npmrepo
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d

# upgrade first, the base is only as fresh as its build day.
# pebble goes: unused, and its Go runtime brings its own advisories. tini reaps zombies
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        mariadb-server \
        mariadb-client \
        supervisor \
        tini \
        ca-certificates \
        gpg \
        gpg-agent \
        gpgv \
        debian-archive-keyring \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/lib/mysql \
    && rm -rf /usr/bin/pebble /var/lib/pebble

RUN groupadd --system --gid 10001 forgerepo \
    && useradd --system --uid 10001 --gid forgerepo --no-create-home \
         --home-dir /nonexistent --shell /usr/sbin/nologin forgerepo

# just the binary. no npm, no npx, no hitchhikers
COPY --from=node /opt/node/bin/node /usr/local/bin/node

WORKDIR /opt/npmrepo
COPY --from=deps /opt/npmrepo/node_modules ./node_modules
COPY app/ ./

COPY docker/my.cnf /etc/mysql/conf.d/npmrepo.cnf
COPY docker/supervisord.conf /etc/supervisor/conf.d/npmrepo.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# db + caches. VOLUME is just a net for plain `docker run`
# no USER line on purpose, scanners whine. supervisor needs root to drop to mysql/forgerepo, which it does
VOLUME ["/data"]

ENV NODE_ENV=production \
    DATA_DIR=/data \
    PORT=4444

EXPOSE 4444

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD node /opt/npmrepo/src/healthcheck.js

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf", "-n"]
