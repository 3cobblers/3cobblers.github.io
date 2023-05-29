---
title:  "V2ray+TLS+Cloudflare防止IP被墙&绕过ChatGPT封锁IP"
categories: [网络]
tags: [V2ray, CloudFlare, ChatGPT]
---


> 使用科学上网时，如果直接用IP，经常莫名奇妙就被干掉了，使用TLS可以降低IP被墙概率；
> 使用ChatGPT时，很多VPS即使是美国IP也无法访问，使用CloudFlare WARP可以绕过该限制；

(本文测试使用Debian 11 x64系统)

### 第一部分 使用V2ray+TLS+WS稳定地科学上网

> TLS需要域名, 并为域名添加A记录指向VPS主机IP, 以下假设已购买域名```my.domain.me```

_这种方式可以大幅降低IP被墙概率, 同时, 速度相较于直连更慢, 适合要求能长久稳定地科学上网需求。_

#### 全手动配置步骤

##### 1. 安装V2ray

[参考fhs-install-v2ray](https://github.com/v2fly/fhs-install-v2ray)

```
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

卸载V2ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
```


脚本执行后, 以下提示即为安装完毕

```bash
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 22454  100 22454    0     0  86030      0 --:--:-- --:--:-- --:--:-- 86361
info: Installing V2Ray v5.4.1 for x86_64
Downloading V2Ray archive: https://github.com/v2fly/v2ray-core/releases/download/v5.4.1/v2ray-linux-64.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 11.2M  100 11.2M    0     0  8591k      0  0:00:01  0:00:01 --:--:--  229M
Downloading verification file for V2Ray archive: https://github.com/v2fly/v2ray-core/releases/download/v5.4.1/v2ray-linux-64.zip.dgst
info: Extract the V2Ray package to /tmp/tmp.uxyOd4J196 and prepare it for installation.
info: Systemd service files have been installed successfully!
warning: The following are the actual parameters for the v2ray service startup.
warning: Please make sure the configuration file path is correctly set.
# /etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf
# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!  # Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json

installed: /usr/local/bin/v2ray
installed: /usr/local/share/v2ray/geoip.dat
installed: /usr/local/share/v2ray/geosite.dat
installed: /usr/local/etc/v2ray/config.json
installed: /var/log/v2ray/
installed: /var/log/v2ray/access.log
installed: /var/log/v2ray/error.log
installed: /etc/systemd/system/v2ray.service
installed: /etc/systemd/system/v2ray@.service
removed: /tmp/tmp.uxyOd4J196
info: V2Ray v5.4.1 is installed.
You may need to execute a command to remove dependent software: apt purge curl unzip
Please execute the command: systemctl enable v2ray; systemctl start v2ray
```

设置开机自启动: ```systemctl enable v2ray.service```


##### 2. 修改配置文件

```bash
vim /usr/local/etc/v2ray/config.json
{
    "inbounds": [
      {
        "port": 443, //监听的端口
        "protocol": "vmess",
        "settings": {
          "clients": [
            {
              "id": "ba7a3545-2c6f-4c3f-bbbb-2d514c197582", // uuid
              "alterId": 0
            }
          ]
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom",
        "settings": {}
      }
    ]
}
```

启动V2ray
```bash
service v2ray stop   // 停止服务
service v2ray start  // 启动服务
service v2ray status // 查看服务状态
```

启动服务后, 可以**用客户端通过上面配置的uuid、端口和服务器IP连接**测试是否配置成功。(测速有速度即时配置成功了)

以上是最低配置的v2ray, 通过服务器IP直接连接, 一般情况下用一段时间就会被墙, 连不上了。下面通过TLS的方式可以提高隐蔽性, 降低被墙概率。

TLS需要域名和证书, 首先配置域名, 假设域名为```my.domain.me```

![](/assets/img/v2ray_tls/dns_A_record.png)

测试使用CloudFlare来管理域名, 在上面DNS记录中添加A记录, 配置```my.domain.me``` -> 服务器IP。

Proxy状态标识了当前记录使用代理方式还是直连方式进行连接, _一般进行域名测试时需要直连, 所以下面安装过程中先要切换为直连状态, 测试完毕后再切换代理状态进一步提高隐蔽性。_


##### 3. 配置证书

生成证书需要用到80端口, 先关闭nginx服务(如果有的话): ```service nginx stop```

安装依赖: ```apt install socat```

安装[acme.sh](https://github.com/acmesh-official/acme.sh/wiki/%E8%AF%B4%E6%98%8E): ```curl  https://get.acme.sh | sh```

```bash
curl  https://get.acme.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1032    0  1032    0     0   2329      0 --:--:-- --:--:-- --:--:--  2329
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  216k  100  216k    0     0   800k      0 --:--:-- --:--:-- --:--:--  800k
[Sat 27 May 2023 12:00:33 PM UTC] Installing from online archive.
[Sat 27 May 2023 12:00:33 PM UTC] Downloading https://github.com/acmesh-official/acme.sh/archive/master.tar.gz
[Sat 27 May 2023 12:00:34 PM UTC] Extracting master.tar.gz
[Sat 27 May 2023 12:00:34 PM UTC] It is recommended to install socat first.
[Sat 27 May 2023 12:00:34 PM UTC] We use socat for standalone server if you use standalone mode.
[Sat 27 May 2023 12:00:34 PM UTC] If you don't use standalone mode, just ignore this warning.
[Sat 27 May 2023 12:00:34 PM UTC] Installing to /root/.acme.sh
[Sat 27 May 2023 12:00:34 PM UTC] Installed to /root/.acme.sh/acme.sh
[Sat 27 May 2023 12:00:34 PM UTC] Installing alias to '/root/.bashrc'
[Sat 27 May 2023 12:00:34 PM UTC] OK, Close and reopen your terminal to start using acme.sh
[Sat 27 May 2023 12:00:34 PM UTC] Installing cron job
no crontab for root
no crontab for root
[Sat 27 May 2023 12:00:34 PM UTC] Good, bash is found, so change the shebang to use bash as preferred.
[Sat 27 May 2023 12:00:35 PM UTC] OK
[Sat 27 May 2023 12:00:35 PM UTC] Install success!
```

> 安装成功后执行```source ~/.bashrc```以确保脚本所设置的命令别名生效

生成证书 (下面的命令会临时监听80端口，确保执行该命令前80端口没有使用)

```bash
~/.acme.sh/acme.sh --issue -d my.domain.me --standalone --keylength ec-256 --force
```

```bash
root@root:~# ~/.acme.sh/acme.sh --issue -d my.domain.me --standalone --keylength ec-256 --force
[Sat 27 May 2023 12:22:47 PM UTC] Using CA: https://acme.zerossl.com/v2/DV90
[Sat 27 May 2023 12:22:47 PM UTC] Standalone mode.
[Sat 27 May 2023 12:22:47 PM UTC] Creating domain key
[Sat 27 May 2023 12:22:47 PM UTC] The domain key is here: /root/.acme.sh/my.domain.me_ecc/my.domain.me.key
[Sat 27 May 2023 12:22:47 PM UTC] Single domain='my.domain.me'
[Sat 27 May 2023 12:22:47 PM UTC] Getting domain auth token for each domain
[Sat 27 May 2023 12:22:52 PM UTC] Getting webroot for domain='my.domain.me'
[Sat 27 May 2023 12:22:53 PM UTC] Verifying: my.domain.me
[Sat 27 May 2023 12:22:53 PM UTC] Standalone mode server
[Sat 27 May 2023 12:22:55 PM UTC] Processing, The CA is processing your order, please just wait. (1/30)
[Sat 27 May 2023 12:22:59 PM UTC] Success
[Sat 27 May 2023 12:22:59 PM UTC] Verify finished, start to sign.
[Sat 27 May 2023 12:22:59 PM UTC] Lets finalize the order.
[Sat 27 May 2023 12:22:59 PM UTC] Le_OrderFinalize='https://acme.zerossl.com/v2/DV90/order/7AqnU0_rqFsld1wfFvlb_w/finalize'
[Sat 27 May 2023 12:23:00 PM UTC] Order status is processing, lets sleep and retry.
[Sat 27 May 2023 12:23:00 PM UTC] Retry after: 15
[Sat 27 May 2023 12:23:16 PM UTC] Polling order status: https://acme.zerossl.com/v2/DV90/order/7AqnU0_rqFsld1wfFvlb_w
[Sat 27 May 2023 12:23:17 PM UTC] Downloading cert.
[Sat 27 May 2023 12:23:17 PM UTC] Le_LinkCert='https://acme.zerossl.com/v2/DV90/cert/c3SeHappfxPRJmuNRXN5Bw'
[Sat 27 May 2023 12:23:18 PM UTC] Cert success.
-----BEGIN CERTIFICATE-----
MIIEDTCCA5KgAwIBAgIRAIzMAfAQjhePuBJ7+Uxo8qYwCgYIKoZIzj0EAwMwSzEL
MAkGA1UEBhMCQVQxEDAOBgNVBAoTB1plcm9TU0wxKjAoBgNVBAMTIVplcm9TU0wg
RUNDIERvbWFpbiBTZWN1cmUgU2l0ZSBDQTAeFw0yMzA1MjcwMDAwMDBaFw0yMzA4
MjUyMzU5NTlaMB8xHTAbBgNVBAMTFHZ0cnNncC5mcmVlYWxpc20udmlwMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEU8CbfSRNzshw01MfGFwiivh9NhHzLU4+pkFF
ZHWN2u7ynQ7Fu69WCGzvXAOsnR1RwpZA7XhK8C9oK/IDxfWOAaOCAoEwggJ9MB8G
A1UdIwQYMBaAFA9r5kvOOUeu9n6QHnnwMJGSyF+jMB0GA1UdDgQWBBRM0DfSDObH
6P+4M/k3tTtUt8nyWTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEEAbIx
AQICTjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
gQwBAgEwgYgGCCsGAQUFBwEBBHwwejBLBggrBgEFBQcwAoY/aHR0cDovL3plcm9z
c2wuY3J0LnNlY3RpZ28uY29tL1plcm9TU0xFQ0NEb21haW5TZWN1cmVTaXRlQ0Eu
Y3J0MCsGCCsGAQUFBzABhh9odHRwOi8vemVyb3NzbC5vY3NwLnNlY3RpZ28uY29t
MIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDxAHYArfe++nz/EMiLnT2cHj4YarRnKV3P
sQwkyoWGNOvcgooAAAGIXSmAHAAABAMARzBFAiEA0+90NSRLfx9D1h6vHHH5XDG3
MHTkpxjj4knrEpdJ2KMCIDImqKIwDrIRR+vHHogcJFH/jeQZii/qsrSx6JeyYlFf
AHcAejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61IAAAGIXSmAfQAABAMA
SDBGAiEAy/sPflL9TQkeguNJ8TGrevx9FUUx+SNXUq56PKt30cYCIQC2yx4kQENP
HIPLScW3RI3UXogeqpaEuY/KgoB8vAR25DAfBgNVHREEGDAWghR2dHJzZ3AuZnJl
ZWFsaXNtLnZpcDAKBggqhkjOPQQDAwNpADBmAjEAp2pF/o0DH/15kflxAqD9CaCL
O1/ngDA/fyxuIhZok5ioa0MDufaLkL5jN4K2/RUhAjEAjIod8fBdaB+tlvMF4Fwr
xfIx15PFx3EzPqy6ZJl6DT23KhGCZ3P+VRRAYD5pVTvn
-----END CERTIFICATE-----
[Sat 27 May 2023 12:23:18 PM UTC] Your cert is in: /root/.acme.sh/my.domain.me_ecc/my.domain.me.cer
[Sat 27 May 2023 12:23:18 PM UTC] Your cert key is in: /root/.acme.sh/my.domain.me_ecc/my.domain.me.key
[Sat 27 May 2023 12:23:18 PM UTC] The intermediate CA cert is in: /root/.acme.sh/my.domain.me_ecc/ca.cer
[Sat 27 May 2023 12:23:18 PM UTC] And the full chain certs is there: /root/.acme.sh/my.domain.me_ecc/fullchain.cer
```


> 证书更新 (有效期只有3个月, 需要90天更新一次证书), 手动更新证书执行: ```~/.acme.sh/acme.sh --renew -d mydomain.com --force --ecc```


安装证书和密钥 (以下命令将证书安装到```/usr/local/etc/v2ray/```下)

```bash
~/.acme.sh/acme.sh --installcert -d my.domain.me --ecc --fullchain-file /usr/local/etc/v2ray/v2ray.cer --key-file /usr/local/etc/v2ray/v2ray.key
[Sat 27 May 2023 12:52:29 PM UTC] Installing key to: /usr/local/etc/v2ray/v2ray.key
[Sat 27 May 2023 12:52:29 PM UTC] Installing full chain to: /usr/local/etc/v2ray/v2ray.cer
```

配置v2ray

```bash
vim /usr/local/etc/v2ray/config.json
{
    "inbounds": [
      {
        "port": 443,
        "protocol": "vmess",
        "settings": {
          "clients": [
            {
              "id": "ba7a3545-2c6f-4c3f-bbbb-2d514c197582", //uuid
              "alterId": 0
            }
          ]
        },
        "streamSettings": {
          "network": "tcp",
          "security": "tls", // 客户端也要选择tls
          "tlsSettings": {
            "certificates": [
              {
                "certificateFile": "/usr/local/etc/v2ray/v2ray.cer",
                "keyFile": "/usr/local/etc/v2ray/v2ray.key"
              }
            ]
          }
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom",
        "settings": {}
      }
    ]
}
```

配置完毕, 重启v2ray服务: ```service v2ray stop && service v2ray start```

此时, 客户端**使用域名```my.domain.me```和上面v2ray配置的信息进行连接**测试应该就可以了。(如果无法连接, 确认DNS记录中是否有添加正确的A记录)

证书测试: [Qualys SSL Labs's SSL Server Test](https://www.ssllabs.com/ssltest/index.html), 打开网站输入域名测试即可。

_参考自[V2ray+TLS配置](https://guide.v2fly.org/advanced/tls.html#%E9%AA%8C%E8%AF%81)_


以上是V2ray+TLS的方式, 避免了直接使用IP进行连接, 一定程度降低被墙概率。下面增加配置服务器程序 (即V2ray+TLS+WebSocket+Web), 让流量经过服务器网站中转到V2ray, 进一步提高隐蔽性。

##### 4. 安装&配置服务器

> 服务器程序可选择nginx、caddy或apache, 其中, caddy会自动生成和更新证书, 不需要手动配置, 先用nginx作为示例

安装nginx: ```apt install nginx```

开机自启动: ```systemctl enable nginx.service```

安装ufw: ```apt install ufw```

查看ufw支持的app:

```bash
ufw app list
Available applications:
  AIM
  Bonjour
  CIFS
  DNS
  Deluge
  IMAP
  IMAPS
  IPP
  ...
```

打开端口:
```bash
ufw allow "Nginx HTTPS" // 也可以这样使用 ufw allow port 443/tcp

// 禁用
ufw delete allow "Nginx HTTP"
// 查看防火墙状态
ufw status
```

启动nginx: ```service nginx start```

此时nginx应该成功安装, 可以在浏览器输入服务IP地址测试是否安装成功。(如果无法房访问, 确认防火墙端口是否打开)

前面的证书是直接配置到v2ray中的, 接下来将证书配置到nginx中。

新建nginx配置文件 (nginx会自动读取```/etc/nginx/conf.d```这个目录下的配置文件)

```bash
vim /etc/nginx/conf.d/v2ray_nginx.conf
server {
    listen 443 ssl;
    listen [::]:443 ssl;

    ssl_certificate       /usr/local/etc/v2ray/v2ray.crt; #证书路径
    ssl_certificate_key   /usr/local/etc/v2ray/v2ray.key; # 密钥路径
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    ssl_protocols         TLSv1.2 TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    server_name           my.domain.me; //域名
    location /mainpage { # 与 V2Ray 配置中的 path 保持一致
      if ($http_upgrade != "websocket") { # WebSocket协商失败时返回404
          return 404;
      }
      proxy_redirect off;
      proxy_pass http://127.0.0.1:41111; # 假设WebSocket监听在本地41111端口
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      # Show real IP in v2ray access.log
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```


_如果使用caddy则不需要配置证书, caddy会自动生成和更新证书, 不需要手动配置_

> 安装配置caddy (参考[caddy Install](https://caddyserver.com/docs/install#debian-ubuntu-raspbian))
> ```bash
> apt install -y debian-keyring debian-archive-keyring apt-transport-https
> curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/> caddy-stable-archive-keyring.gpg
> curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
> apt update
> apt install caddy
> ```
>
> 修改caddy配置文件
> ```bash
> vim /var/lib/caddy/.config/caddy
> my.domain.me {
>     log {
>         output file /etc/caddy/caddy.log
>     }
>     tls {
>         protocols tls1.2 tls1.3
>         ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
>         curves x25519
>     }
>     @v2ray_websocket {
>         path /mainpage
>         header Connection Upgrade
>         header Upgrade websocket
>     }
>     reverse_proxy @v2ray_websocket localhost:41111
> }
> ```


配置v2ray

```bash
vim /usr/local/etc/v2ray/config.json
{
    "inbounds": [
      {
        "port": 41111,
        "listen":"127.0.0.1", //只监听 127.0.0.1，避免除本机外的机器探测到开放了41111端口
        "protocol": "vmess",
        "settings": {
          "clients": [
            {
              "id": "ba7a3545-2c6f-4c3f-bbbb-2d514c197582",
              "alterId": 0
            }
          ]
        },
        "streamSettings": {
          "network": "ws",
          "wsSettings": {
          "path": "/mainpage" //客户端连接path需要填正确
          }
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom",
        "settings": {}
      }
    ]
}
```

配置完毕重启nginx和v2ray:
```
service nginx stop && service nginx start
service v2ray stop && service v2ray start
```

v2ray客户端使用域名连接即可 (注意path、nerwork和uuid要填正确, 端口填443, 因为实际上流量是通过nginx转发到v2ray)


以上参考自[新V2Ray白话文指南](https://guide.v2fly.org/advanced/wss_and_web.html#%E6%9C%8D%E5%8A%A1%E5%99%A8%E9%85%8D%E7%BD%AE)


最后CDN配置 (在Cloudflare的DNS记录中切换代理模式和DNS模式即可)

另外, 在CloudFlare中的域名管理, 设置安全级别和白名单:

Security -> Settings -> Security Level -> Essentially Off

Security -> WAF -> Tools -> 添加China (CN) allow（白名单）

Network -> 开启所有功能



#### 使用一键脚本配置

一键脚本安装v2ray比较简单, 直接执行脚本：```bash <(curl -s -L https://git.io/v2ray-setup.sh)```。

如果需要配置TLS, 安装完v2ray时, **选择WS+TLS的方式 按步骤操作即可**。安装完后也可输入v2ray修改配置, _脚本默认安装caddy作为服务器程序, 不需要手动配置证书_。

_选择WS+TLS安装时需注意: 安装前DNS记录需要设置为直连模式即DNS Only, 因为安装过程中, 程序需要验证域名解析是否正确, 可在安装完毕后根据需要决定是否切换为代理模式(一般代理模式安全级别更高, 但速度也更慢)_


### 第二部分 CloudFlare WARP绕过ChatGPT封锁IP

利用WARP解除ChatGPT地域限制, 先查看本机出口信息

```bash
curl ipinfo.io
{
  "ip": "45.76.156.40",
  "hostname": "45.76.156.40.vultrusercontent.com",
  "city": "root",
  "region": "root",
  "country": "SG",
  "loc": "1.3215,103.6957",
  "org": "AS20473 The Constant Company, LLC",
  "postal": "627753",
  "timezone": "Asia/root",
  "readme": "https://ipinfo.io/missingauth"
```

或查看chatgpt是否可用

```bash
bash <(curl -Ls https://raw.githubusercontent.com/missuo/OpenAI-Checker/main/openai.sh)
```

安装cloudflare-warp (参考[cloudflare repository install](https://pkg.cloudflareclient.com/install))

```bash
curl https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
apt update
apt install cloudflare-warp
```

注册: ```warp-cli register```

```bash
root@root:~# warp-cli register
NOTICE:

Cloudflare only collects limited DNS query and traffic data (excluding payload)
that is sent to our network when you have the app enabled on your device. We
will not sell, rent, share, or otherwise disclose your personal information to
anyone, except as otherwise described in this Policy, without first providing
you with notice and the opportunity to consent. All information is handled in
accordance with our Privacy Policy.

More information is available at:
- https://www.cloudflare.com/application/terms/
- https://www.cloudflare.com/application/privacypolicy/

Accept Terms of Service and Privacy Policy? [y/N] y

Success
```

设置代理模式: ```warp-cli set-mode proxy```

连接: ```warp-cli connect```

确认状态: ```curl https://www.cloudflare.com/cdn-cgi/trace/``` 确认warp为on

始终开启: ```warp-cli enable-always-on```

查看状态: ```warp-cli warp-stats```

以上参考[WARP Linux desktop client](https://developers.cloudflare.com/warp-client/get-started/linux/)


修改v2ray配置文件 (在outbounds和routing标签下添加下面标注出的内容)

```bash
vim /etc/v2ray/config.json // 脚本安装时默认配置文件路径
或 vim /usr/local/etc/v2ray/config.json 手动安装时配置文件路径
{
  "inbounds": [
    {
      "port": 41111,
      "listen":"127.0.0.1",//只监听 127.0.0.1，避免除本机外的机器探测到开放了41111端口
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "ba7a3545-2c6f-4c3f-bbbb-2d514c197582",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
        "path": "/mainpage"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
    },

    /////添加以下内容/////
    {
      "tag": "warp",
      "protocol": "socks",
      "settings": {
          "servers": [
              {
                  "address": "127.0.0.1",
                  "port": 40000,
                  "users": []
              }
          ]
          }
      }
      ////////////////////

  ],
  "routing": {
      "rules": [
          /////添加路由规则/////
          {
              "type": "field",
              "domain": [
                  "openai.com",
                  "ai.com",
                  "sentry.io", // 2023.4月新增策略
                  "intercom.io",
                  "featuregates.org",
                  "statsigapi.net"
              ],
              "outboundTag": "warp"
          }
          /////添加路由规则/////
      ]
  }
}
```

重启v2ray服务

```bash
service v2ray stop
service v2ray start
service v2ray status
```

再次查看出口信息, 提示以下信息即为配置成功了

```bash
curl -x "socks5://127.0.0.1:40000" ipinfo.io
{
  "ip": "111.28.222.33",
  "city": "root",
  "region": "root",
  "country": "US",
  "loc": "1.2834,103.8511",
  "org": "AS13335 Cloudflare, Inc.",
  "postal": "048617",
  "timezone": "America/root",
  "readme": "https://ipinfo.io/missingauth"
}
```

_经测试, 被ChatGPT限制的IP经过以上配置后在Windows浏览器上可以访问, 在Android设备上依然无法访问。_


### 参考资料

https://github.com/v2fly/fhs-install-v2ray
https://caddyserver.com/docs/install#debian-ubuntu-raspbian
https://guide.v2fly.org/advanced/tls.html
https://guide.v2fly.org/advanced/wss_and_web.html
https://pkg.cloudflareclient.com/install
https://developers.cloudflare.com/warp-client/get-started/linux/
https://github.com/fqfree/ssr/blob/master/ssr-advanced/v2ray-ws-tls-web.md
https://ping.pe
https://ping.sx/ping
