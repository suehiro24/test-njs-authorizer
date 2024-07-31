local _M = {}

local jwt = require "resty.jwt"
local http = require "resty.http"
local cjson = require "cjson"

local EXPECTED_ISSUER = "https://login.microsoftonline.com/consumers/v2.0" -- ここに期待する発行者を設定
local EXPECTED_SCOPE = "your-expected-scope" -- ここに期待するスコープを設定

function _M.verify_jwt()
    -- JWTを取得
    local token = ngx.var.http_Authorization
    if not token or not token:find("Bearer ") then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("Unauthorized: No token provided")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- "Bearer " プレフィックスを削除
    token = token:sub(8)

    -- JWKを取得 (URLから)
    local httpc = http.new()
    local res, err = httpc:request_uri("https://login.microsoftonline.com/common/discovery/keys", {
        method = "GET",
        ssl_verify = false
    })

    if not res then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.log(ngx.ERR, "Internal Server Error: failed to request jwks")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local jwks, err = cjson.decode(res.body)
    if not jwks then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.log(ngx.ERR, "Internal Server Error: failed to decode jwks")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- JWTを検証
    local decoded = jwt:verify(token, { keys = jwks.keys })
    if not decoded or not decoded.verified then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, "Unauthorized: Invalid token")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- ペイロードをデコード
    local payload = decoded.payload
    if not payload then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, "Unauthorized: Invalid payload")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- 発行者を検証
    if not payload.iss or payload.iss ~= EXPECTED_ISSUER then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, "Unauthorized: Invalid issuer")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- スコープを検証
    if not payload.scp or payload.scp ~= EXPECTED_SCOPE then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, "Unauthorized: Invalid scope")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- 保護されたリソースにアクセスを許可
    ngx.status = ngx.HTTP_OK
    ngx.say("Authorized")
end

return _M
