FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6

ENV NODE_ENV=production \
    PARIMIT_HOST=127.0.0.1 \
    PARIMIT_PORT=8787 \
    PARIMIT_DB_PATH=/data/parimit.db \
    PARIMIT_DEMO_MODE=true \
    PARIMIT_AUTH_MODE=demo_headers

WORKDIR /app

COPY --chown=node:node package.json tsconfig.json LICENSE NOTICE ./

COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

RUN mkdir -p /data && chown node:node /data

USER node
EXPOSE 8787
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8787/v1/safety').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["npm", "start"]
