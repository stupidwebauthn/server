FROM oven/bun:1-alpine AS base
WORKDIR /app

FROM base AS install
RUN mkdir -p /temp/dev
COPY package.json bun.lockb /temp/dev/
RUN cd /temp/dev && bun install --frozen-lockfile


FROM base AS release
COPY --from=install /temp/dev/node_modules node_modules
COPY . .

EXPOSE 3000/tcp
ENTRYPOINT [ "bun", "run", "start" ]
