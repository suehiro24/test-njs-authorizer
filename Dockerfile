FROM openresty/openresty:alpine

# Install dependencies for 'opm get' execution
RUN apk add --no-cache curl perl

# Install modules for jwt validation
RUN /usr/local/openresty/bin/opm get SkyLothar/lua-resty-jwt
RUN /usr/local/openresty/bin/opm get pintsized/lua-resty-http

# nginx configuration file
COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY ./jwt_auth.lua /usr/local/openresty/nginx/lua/jwt_auth.lua

EXPOSE 80

CMD ["openresty", "-g", "daemon off;"]