# ⚠️ INTENTIONALLY INSECURE (container demo):
#   - full Debian 11 "bullseye" base image: old OS packages with many known CVEs
#   - single stage: build tools and dev dependencies end up in the runtime image
#   - runs as root, no HEALTHCHECK
FROM node:22-bullseye
WORKDIR /app
COPY . .
RUN npm install && npm run build
EXPOSE 3000
CMD ["npm", "start"]
