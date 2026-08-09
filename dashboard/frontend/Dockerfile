# SOAR Frontend Dockerfile
# Stage 1: Build
FROM node:18-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Pass API URL during build if needed
ARG VITE_API_URL=http://localhost:3000
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:stable-alpine

# Copy build output to nginx public folder
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config if you have one, or use default
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
