FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps
COPY . .
RUN npm run build && npm prune --omit=dev --legacy-peer-deps

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S naxium && adduser -S naxium -G naxium
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
USER naxium
EXPOSE 8787
ENV NAXIUM_PORT=8787
ENV NAXIUM_HOST=0.0.0.0
ENV NAXIUM_SECURITY_LEVEL=6
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.NAXIUM_PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server/httpServer.js"]
