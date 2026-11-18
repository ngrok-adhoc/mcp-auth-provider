FROM node:24-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY bin/ ./bin/
COPY lib/ ./lib/

USER node
ENTRYPOINT ["node", "bin/mcp-oauth-provider.mjs"]
CMD ["--no-debug"]
