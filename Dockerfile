FROM oven/bun AS base
WORKDIR /app

COPY bun.lockb . 
COPY package.json . 

# Install dependencies
RUN bun install --frozen-lockfile

COPY . . 

EXPOSE 3000/tcp
ENTRYPOINT [ "bun", "run", "start" ]
