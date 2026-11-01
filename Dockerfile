FROM node:26.13.0-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9

ENV NODE_ENV=production \
    PARIMIT_HOST=127.0.0.1 \
    PARIMIT_PORT=8787 \
    PARIMIT_DB_PATH=/data/parimit.db \
    PARIMIT_DEMO_MODE=true \
    PARIMIT_AUTH_MODE=demo_headers

WORKDIR /app

COPY --chown=node:node package.json package-lock.json tsconfig.json LICENSE NOTICE ./

# The application has no third-party production dependency. npm ci still
# verifies that the committed lockfile and package metadata agree.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

RUN mkdir -p /data && chown node:node /data

USER node
EXPOSE 8787
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8787/v1/safety').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["npm", "start"]
