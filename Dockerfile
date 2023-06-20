FROM nginxinc/nginx-unprivileged:1.25.0

ADD nginx.conf /etc/nginx/conf.d/default.conf
ADD index.html /usr/share/nginx/html/index.html
