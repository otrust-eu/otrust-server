FROM node:18-alpine

WORKDIR /app

# Installera beroenden för leveldb
RUN apk add --no-cache python3 make g++ bash

# Sätt NODE_ENV
ENV NODE_ENV=production

# Skapa mappar för blockchain-data och loggar
RUN mkdir -p /app/blockchain /app/logs

# Kopiera package-filer
COPY package*.json ./

# Installera beroenden
RUN npm ci --only=production

# Kopiera applikationskod
COPY . .

# Skapa icke-root användare
RUN addgroup -S otrust && adduser -S otrust -G otrust 

# Sätt ägarskap
RUN chown -R otrust:otrust /app

# Byt till icke-root användare
USER otrust

# Exponera porten
EXPOSE 3000

# Hälsokontroll
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Kommando för att köra applikationen
CMD ["node", "server.js"]
