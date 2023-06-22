FROM pandoc/core:3.1 as builder

WORKDIR /app

ADD README.md README.md
RUN pandoc README.md --standalone -o out.html --toc --metadata title="Let's build a container runtime"

FROM nginxinc/nginx-unprivileged:1.25.0

ADD nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/out.html /usr/share/nginx/html/index.html
