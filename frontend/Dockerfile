# ======================================================
# SASTGuard frontend image - multi-stage build.
# Stage 1 builds the Vite app (needs Node 18+), stage 2 serves it with nginx.
# ======================================================
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
# Use npm install (no lockfile committed); generates one inside the image.
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1
CMD ["nginx", "-g", "daemon off;"]
