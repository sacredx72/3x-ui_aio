mode: rule
log-level: warning
mixed-port: 10000
unified-delay: true
allow-lan: true
tcp-concurrent: true
enable-process: true
find-process-mode: always
global-client-fingerprint: chrome
keep-alive-interval: 30
geo-auto-update: true
geo-update-interval: 168

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports:
        - 80
        - 8080-8880
      override-destination: true
    TLS:
      ports:
        - 443
        - 8443
      override-destination: true
    QUIC:
      ports:
        - 443
        - 8443
      override-destination: true
  skip-domain:
    - "+.push.apple.com"
    - "+.crl.apple.com"
    - "Mijia.*"
    - "+.srv.nintendo.net"
    - "+.stun.playstation.net"
    - "+.xboxlive.com"
    - "tun.msftconnecttest.com"

dns:
  enable: true
  prefer-h3: true
  use-hosts: true
  use-system-hosts: true
  listen: 127.0.0.1:6868
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  cache-algorithm: arc
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.localhost"
    - "*.home.arpa"
    - "localhost.ptlogin2.qq.com"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
    - "msftconnecttest.com"
    - "localhost.sec.qq.com"
    - "+.srv.nintendo.net"
    - "+.stun.playstation.net"
    - "+.xboxlive.com"
    - "*.mshome.net"
    - "*.miHoYo.com"
    - "*.mihoyo.com"
    - "+.star.cq.qq.com"
    - "+.logon.battlenet.com.cn"
    - "+.push.apple.com"
    - "+.crl.apple.com"
    - "+.steamcontent.com"
    - "+.steamstatic.com"
    - "+.steamcdn-a.akamaihd.net"
    - "+.steam-chat.com"
    - "+.max.ru"
    - "+.max.com"
    - "+.maxcdn.ru"
    - "+.vk.com"
    - "+.vk-portal.net"
    - "+.vk-cdn.net"
    - "+.vkuser.net"
    - "+.vkvideo.ru"
    - "+.vk-apps.com"
    - "+.vkuservideo.net"
    - "+.userapi.com"
    - "+.vkforms.ru"
    - "+.vkcdnglb.net"
    - "+.ok.ru"
    - "+.odnoklassniki.ru"
    - "+.mycdn.me"
    - "+.mail.ru"
    - "+.e.mail.ru"
    - "+.m.mail.ru"
    - "+.r.mail.ru"
    - "+.auth.mail.ru"
    - "+.account.mail.ru"
    - "+.imgsmail.ru"
    - "+.tamtam.chat"
    - "+.webinar.ru"
    - "+.loginza.ru"
    - "+.yandex.ru"
    - "+.yandex.net"
    - "+.yandex.com"
    - "+.ya.ru"
    - "+.kinopoisk.ru"
    - "+.music.yandex.ru"
    - "+.market.yandex.ru"
    - "+.eda.yandex.ru"
    - "+.lavka.yandex.ru"
    - "+.disk.yandex.ru"
    - "+.pdd.yandex.ru"
    - "+.moikrug.ru"
    - "+.narod.ru"
    - "+.turbopages.org"
    - "+.strm.yandex.net"
    - "+.yastatic.net"
    - "+.yastat.net"
    - "+.sberbank.ru"
    - "+.sber.ru"
    - "+.tinkoff.ru"
    - "+.tinkov.ru"
    - "+.vtb.ru"
    - "+.alfabank.ru"
    - "+.gazprombank.ru"
    - "+.openbank.ru"
    - "+.open.ru"
    - "+.raiffeisen.ru"
    - "+.psbank.ru"
    - "+.sovcombank.ru"
    - "+.rsb.ru"
    - "+.homecredit.ru"
    - "+.uralsib.ru"
    - "+.mkb.ru"
    - "+.rosbank.ru"
    - "+.sravni.ru"
    - "+.banki.ru"
    - "+.qiwi.com"
    - "+.yu-money.ru"
    - "+.yoomoney.ru"
    - "+.webmoney.ru"
    - "+.mts.ru"
    - "+.bank.mts.ru"
    - "+.megafon.ru"
    - "+.beeline.ru"
    - "+.tele2.ru"
    - "+.gosuslugi.ru"
    - "+.gosuslugi.kz"
    - "+.esia.gosuslugi.ru"
    - "+.nalog.gov.ru"
    - "+.nalog.ru"
    - "+.mos.ru"
    - "+.mfc.ru"
    - "+.mvd.ru"
    - "+.minjust.gov.ru"
    - "+.russianpost.ru"
    - "+.pochta.ru"
    - "+.mfms.dks.ru"
    - "+.sfr.gov.ru"
    - "+.pfr.gov.ru"
    - "+.sudact.ru"
    - "+.kad.arbitr.ru"
    - "+.my.e-government.ru"
    - "+.cbr.ru"
    - "+.banki.ru"
    - "+.e-disclosure.ru"
    - "+.wildberries.ru"
    - "+.wb.ru"
    - "+.wbcontent.net"
    - "+.wbx5.ru"
    - "+.ozon.ru"
    - "+.ozonusercontent.com"
    - "+.megamarket.ru"
    - "+.beru.ru"
    - "+.aliexpress.ru"
    - "+.lamoda.ru"
    - "+.dns-shop.ru"
    - "+.mvideo.ru"
    - "+.eldorado.ru"
    - "+.citilink.ru"
    - "+.2gis.com"
    - "+.2gis.ru"
    - "+.sbermarket.ru"
    - "+.perekrestok.ru"
    - "+.magnit.ru"
    - "+.delivery-club.ru"
    - "+.samokat.ru"
    - "+.ikea.ru"
    - "+.hh.ru"
    - "+.rabota.ru"
    - "+.superjob.ru"
    - "+.rutube.ru"
    - "+.ivi.ru"
    - "+.okko.tv"
    - "+.start.ru"
    - "+.more.tv"
    - "+.wink.rt.ru"
    - "+.premier.one"
    - "+.gpm_tv.ru"
    - "+.taxi.yandex.ru"
    - "+.citymobil.ru"
    - "+.gett.com"
    - "+.reg.ru"
    - "+.nic.ru"
    - "+.timepad.ru"
    - "+.tass.ru"
    - "+.ria.ru"
    - "+.interfax.ru"
    - "+.rbc.ru"
    - "+.kommersant.ru"
    - "+.lenta.ru"
    - "+.gazeta.ru"
    - "+.iz.ru"
    - "+.rt.com"
    - "+.cloudflare-dns.com"
    - "+.dns.google"

  default-nameserver:
    - 77.88.8.8
    - 195.208.4.1
    - system
  proxy-server-nameserver:
    - 77.88.8.8
    - 195.208.4.1
    - system
  direct-nameserver:
    - tls://77.88.8.8#DIRECT
    - tls://8.8.8.8#DIRECT
    - 195.208.4.1#DIRECT
    - system
  nameserver:
    - https://dns.cloudflare/dns-query#PROXY
    - https://dns.google/dns-query#PROXY
    - tls://8.8.4.4#PROXY
  fallback:
    - tls://8.8.8.8#PROXY
    - tls://1.1.1.1#PROXY
    - https://dns.cloudflare/dns-query#PROXY
  fallback-filter:
    geoip: true
    geoip-code: RU
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
    domain:
      - "+.google.com"
      - "+.facebook.com"
      - "+.youtube.com"
      - "+.twitter.com"
      - "+.x.com"

# v10 FIX: proxy-providers с чужим доменом (ihpan.nad.cloud-ip.cc) убран.
# LucX-UI / 3x-ui при выдаче Clash-подписки (https://DOMAIN/CLASH_PATH/subId)
# сам вставляет proxies[] из inbound'ов клиента. Группы берут их через
# include-all-proxies: true — без статической URL и без ${SUB_ID}.
# (Раньше use: [sub] тянул битый provider → пустые группы.)

proxy-groups:

  - name: 🌐 Internet
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)
      - DIRECT

  - name: 🌍 VPN (Manual)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hijacking.png
    type: select
    include-all-proxies: true
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)

  - name: 🚀 Auto (Fastest)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: url-test
    tolerance: 100
    url: https://cp.cloudflare.com/generate_204
    interval: 120
    include-all-proxies: true

  - name: 🎯 Balance (Load)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/LoadBalance.png
    type: load-balance
    strategy: consistent-hashing
    url: https://cp.cloudflare.com/generate_204
    interval: 180
    tolerance: 150
    include-all-proxies: true

  - name: 🔄 Failover
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Availability.png
    type: fallback
    url: https://cp.cloudflare.com/generate_204
    interval: 120
    tolerance: 100
    include-all-proxies: true

  - name: 🔀 Round Robin
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: load-balance
    strategy: round-robin
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    include-all-proxies: true

  - name: ▶️ YouTube
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)
  - name: ➤ Telegram
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 💬 Discord
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Discord.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: ➤ WhatsApp
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Facebook.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 🤖 AI Services
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 🎬 Streaming
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Streaming.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🌍 VPN (Manual)

  - name: 🇷🇺 Blocked RU
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🌍 VPN (Manual)
      - DIRECT

  - name: PROXY
    type: select
    hidden: true
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

rule-providers:

  oisd_big:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/oisd/big.mrs
    path: ./oisd/big.mrs
    interval: 86400

  oisd_small:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/oisd/small.mrs
    path: ./oisd/small.mrs
    interval: 86400

  telegram-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/telegram.mrs
    path: ./rule-sets/telegram-ips.mrs

  telegram-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/telegram.mrs
    path: ./rule-sets/telegram-domains.mrs

  whatsapp-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/whatsapp.mrs
    path: ./rule-sets/whatsapp-domains.mrs

  facebook-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/facebook.mrs
    path: ./rule-sets/facebook-ips.mrs
  discord_domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/discord.mrs
    path: ./rule-sets/discord_domains.mrs

  discord_voiceips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/discord-voice-ip-list.mrs
    path: ./rule-sets/discord_voiceips.mrs

  youtube:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/youtube.mrs
    path: ./rule-sets/youtube.mrs

  torrent-trackers:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-trackers.mrs
    path: ./rule-sets/torrent-trackers.mrs
    interval: 86400

  torrent-clients:
    type: http
    behavior: classical
    format: yaml
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-clients.yaml
    path: ./rule-sets/torrent-clients.yaml
    interval: 86400

  refilter_domains:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/domain-rule.mrs
    path: ./re-filter/domain-rule.mrs
    interval: 86400

  refilter_ipsum:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/ip-rule.mrs
    path: ./re-filter/ip-rule.mrs
    interval: 86400

  ru-bundle:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/ru-bundle/rule.mrs
    path: ./ru-bundle/rule.mrs
    interval: 86400

  ai-services:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/openai.mrs
    path: ./rule-sets/ai-services.mrs
    interval: 86400

  google:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/google.mrs
    path: ./rule-sets/google.mrs
    interval: 86400

  streaming:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/netflix.mrs
    path: ./rule-sets/streaming.mrs
    interval: 86400

  blocked-ru:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/ru-bundle/blocked.mrs
    path: ./ru-bundle/blocked.mrs
    interval: 86400

  microsoft:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/microsoft.mrs
    path: ./rule-sets/microsoft.mrs
    interval: 86400

rules:
  - GEOIP,private,DIRECT,no-resolve
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT

  - RULE-SET,oisd_big,REJECT
  - RULE-SET,oisd_small,REJECT

  - OR,((DOMAIN-SUFFIX,ipwhois.app),(DOMAIN-SUFFIX,ipwho.is),(DOMAIN-SUFFIX,api.ip.sb),(DOMAIN-SUFFIX,ipapi.co),(DOMAIN-SUFFIX,ipinfo.io),(DOMAIN-SUFFIX,ip-api.com),(DOMAIN-SUFFIX,ifconfig.me),(DOMAIN-SUFFIX,icanhazip.com),(DOMAIN-SUFFIX,api.my-ip.io)),🌐 Internet

  - OR,((RULE-SET,telegram-ips),(RULE-SET,telegram-domains)),➤ Telegram
  - PROCESS-NAME,org.telegram.messenger,➤ Telegram
  - PROCESS-NAME,Telegram,➤ Telegram
  - PROCESS-NAME,telegram.exe,➤ Telegram

  - OR,((RULE-SET,facebook-ips),(RULE-SET,whatsapp-domains)),➤ WhatsApp
  - PROCESS-NAME,WhatsApp.exe,➤ WhatsApp
  - PROCESS-NAME,WhatsApp,➤ WhatsApp

  - OR,((RULE-SET,discord_domains),(RULE-SET,discord_voiceips)),💬 Discord
  - PROCESS-NAME,Discord.exe,💬 Discord
  - PROCESS-NAME,Discord,💬 Discord
  - PROCESS-NAME,discord,💬 Discord
  - PROCESS-NAME,Discord Helper,💬 Discord
  - PROCESS-NAME,Discord Helper (Renderer),💬 Discord

  - RULE-SET,youtube,▶️ YouTube
  - RULE-SET,google,▶️ YouTube

  - RULE-SET,ai-services,🤖 AI Services

  - RULE-SET,streaming,🎬 Streaming

  - OR,((RULE-SET,torrent-clients),(RULE-SET,torrent-trackers)),DIRECT
  - PROCESS-NAME,qBittorrent.exe,DIRECT
  - PROCESS-NAME,qbittorrent.exe,DIRECT
  - PROCESS-NAME,Transmission.exe,DIRECT
  - PROCESS-NAME,transmission-daemon,DIRECT
  - PROCESS-NAME,Deluge.exe,DIRECT
  - PROCESS-NAME,utorrent.exe,DIRECT
  - PROCESS-NAME,bitcomet.exe,DIRECT

  - RULE-SET,refilter_domains,🌐 Internet
  - RULE-SET,refilter_ipsum,🌐 Internet,no-resolve
  - RULE-SET,blocked-ru,🌐 Internet

  - DOMAIN-SUFFIX,max.ru,DIRECT
  - DOMAIN-SUFFIX,max.com,DIRECT
  - DOMAIN-SUFFIX,cdn.max.ru,DIRECT

  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,vk-portal.net,DIRECT
  - DOMAIN-SUFFIX,vk-cdn.net,DIRECT
  - DOMAIN-SUFFIX,vkuser.net,DIRECT
  - DOMAIN-SUFFIX,vkvideo.ru,DIRECT
  - DOMAIN-SUFFIX,vk-apps.com,DIRECT
  - DOMAIN-SUFFIX,vkuservideo.net,DIRECT
  - DOMAIN-SUFFIX,userapi.com,DIRECT
  - DOMAIN-SUFFIX,vkforms.ru,DIRECT
  - DOMAIN-SUFFIX,vkcdnglb.net,DIRECT
  - DOMAIN-SUFFIX,ok.ru,DIRECT
  - DOMAIN-SUFFIX,odnoklassniki.ru,DIRECT
  - DOMAIN-SUFFIX,mycdn.me,DIRECT
  - DOMAIN-SUFFIX,mail.ru,DIRECT
  - DOMAIN-SUFFIX,e.mail.ru,DIRECT
  - DOMAIN-SUFFIX,m.mail.ru,DIRECT
  - DOMAIN-SUFFIX,r.mail.ru,DIRECT
  - DOMAIN-SUFFIX,auth.mail.ru,DIRECT
  - DOMAIN-SUFFIX,account.mail.ru,DIRECT
  - DOMAIN-SUFFIX,imgsmail.ru,DIRECT
  - DOMAIN-SUFFIX,tamtam.chat,DIRECT
  - DOMAIN-SUFFIX,webinar.ru,DIRECT
  - DOMAIN-SUFFIX,loginza.ru,DIRECT

  - DOMAIN-SUFFIX,yandex.ru,DIRECT
  - DOMAIN-SUFFIX,yandex.net,DIRECT
  - DOMAIN-SUFFIX,yandex.com,DIRECT
  - DOMAIN-SUFFIX,ya.ru,DIRECT
  - DOMAIN-SUFFIX,kinopoisk.ru,DIRECT
  - DOMAIN-SUFFIX,music.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,market.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,eda.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,lavka.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,disk.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,pdd.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,moikrug.ru,DIRECT
  - DOMAIN-SUFFIX,narod.ru,DIRECT
  - DOMAIN-SUFFIX,turbopages.org,DIRECT
  - DOMAIN-SUFFIX,yastatic.net,DIRECT
  - DOMAIN-SUFFIX,yastat.net,DIRECT
  - DOMAIN-SUFFIX,cloud.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,clck.yandex.ru,DIRECT

  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - DOMAIN-SUFFIX,sber.ru,DIRECT
  - DOMAIN-SUFFIX,tinkoff.ru,DIRECT
  - DOMAIN-SUFFIX,tinkov.ru,DIRECT
  - DOMAIN-SUFFIX,vtb.ru,DIRECT
  - DOMAIN-SUFFIX,alfabank.ru,DIRECT
  - DOMAIN-SUFFIX,gazprombank.ru,DIRECT
  - DOMAIN-SUFFIX,openbank.ru,DIRECT
  - DOMAIN-SUFFIX,open.ru,DIRECT
  - DOMAIN-SUFFIX,raiffeisen.ru,DIRECT
  - DOMAIN-SUFFIX,psbank.ru,DIRECT
  - DOMAIN-SUFFIX,sovcombank.ru,DIRECT
  - DOMAIN-SUFFIX,rsb.ru,DIRECT
  - DOMAIN-SUFFIX,homecredit.ru,DIRECT
  - DOMAIN-SUFFIX,uralsib.ru,DIRECT
  - DOMAIN-SUFFIX,mkb.ru,DIRECT
  - DOMAIN-SUFFIX,rosbank.ru,DIRECT
  - DOMAIN-SUFFIX,sravni.ru,DIRECT
  - DOMAIN-SUFFIX,banki.ru,DIRECT
  - DOMAIN-SUFFIX,qiwi.com,DIRECT
  - DOMAIN-SUFFIX,yu-money.ru,DIRECT
  - DOMAIN-SUFFIX,yoomoney.ru,DIRECT
  - DOMAIN-SUFFIX,webmoney.ru,DIRECT
  - DOMAIN-SUFFIX,cbr.ru,DIRECT
  - DOMAIN-SUFFIX,e-disclosure.ru,DIRECT

  - DOMAIN-SUFFIX,mts.ru,DIRECT
  - DOMAIN-SUFFIX,bank.mts.ru,DIRECT
  - DOMAIN-SUFFIX,megafon.ru,DIRECT
  - DOMAIN-SUFFIX,beeline.ru,DIRECT
  - DOMAIN-SUFFIX,tele2.ru,DIRECT
  - DOMAIN-SUFFIX,rostelecom.ru,DIRECT

  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,gosuslugi.kz,DIRECT
  - DOMAIN-SUFFIX,esia.gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,nalog.gov.ru,DIRECT
  - DOMAIN-SUFFIX,nalog.ru,DIRECT
  - DOMAIN-SUFFIX,mos.ru,DIRECT
  - DOMAIN-SUFFIX,mfc.ru,DIRECT
  - DOMAIN-SUFFIX,mvd.ru,DIRECT
  - DOMAIN-SUFFIX,minjust.gov.ru,DIRECT
  - DOMAIN-SUFFIX,russianpost.ru,DIRECT
  - DOMAIN-SUFFIX,pochta.ru,DIRECT
  - DOMAIN-SUFFIX,mfms.dks.ru,DIRECT
  - DOMAIN-SUFFIX,sfr.gov.ru,DIRECT
  - DOMAIN-SUFFIX,pfr.gov.ru,DIRECT
  - DOMAIN-SUFFIX,sudact.ru,DIRECT
  - DOMAIN-SUFFIX,kad.arbitr.ru,DIRECT
  - DOMAIN-SUFFIX,my.e-government.ru,DIRECT
  - DOMAIN-SUFFIX,gosmonitor.ru,DIRECT
  - DOMAIN-SUFFIX,e-government.ru,DIRECT
  - DOMAIN-SUFFIX,uslugi.mos.ru,DIRECT

  - DOMAIN-SUFFIX,wildberries.ru,DIRECT
  - DOMAIN-SUFFIX,wb.ru,DIRECT
  - DOMAIN-SUFFIX,wbcontent.net,DIRECT
  - DOMAIN-SUFFIX,wbx5.ru,DIRECT
  - DOMAIN-SUFFIX,ozon.ru,DIRECT
  - DOMAIN-SUFFIX,ozonusercontent.com,DIRECT
  - DOMAIN-SUFFIX,megamarket.ru,DIRECT
  - DOMAIN-SUFFIX,beru.ru,DIRECT
  - DOMAIN-SUFFIX,aliexpress.ru,DIRECT
  - DOMAIN-SUFFIX,lamoda.ru,DIRECT
  - DOMAIN-SUFFIX,dns-shop.ru,DIRECT
  - DOMAIN-SUFFIX,mvideo.ru,DIRECT
  - DOMAIN-SUFFIX,eldorado.ru,DIRECT
  - DOMAIN-SUFFIX,citilink.ru,DIRECT
  - DOMAIN-SUFFIX,2gis.com,DIRECT
  - DOMAIN-SUFFIX,2gis.ru,DIRECT
  - DOMAIN-SUFFIX,sbermarket.ru,DIRECT
  - DOMAIN-SUFFIX,perekrestok.ru,DIRECT
  - DOMAIN-SUFFIX,magnit.ru,DIRECT
  - DOMAIN-SUFFIX,delivery-club.ru,DIRECT
  - DOMAIN-SUFFIX,samokat.ru,DIRECT
  - DOMAIN-SUFFIX,ikea.ru,DIRECT
  - DOMAIN-SUFFIX,leroymerlin.ru,DIRECT
  - DOMAIN-SUFFIX,petrovich.ru,DIRECT
  - DOMAIN-SUFFIX,vprok.ru,DIRECT

  - DOMAIN-SUFFIX,hh.ru,DIRECT
  - DOMAIN-SUFFIX,rabota.ru,DIRECT
  - DOMAIN-SUFFIX,superjob.ru,DIRECT
  - DOMAIN-SUFFIX,work.ua,DIRECT
  - DOMAIN-SUFFIX,avito.ru,DIRECT
  - DOMAIN-SUFFIX,youla.ru,DIRECT

  - DOMAIN-SUFFIX,taxi.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,citymobil.ru,DIRECT
  - DOMAIN-SUFFIX,gettaxi.com,DIRECT
  - DOMAIN-SUFFIX,rzd.ru,DIRECT
  - DOMAIN-SUFFIX,tutu.ru,DIRECT

  - DOMAIN-SUFFIX,rutube.ru,DIRECT
  - DOMAIN-SUFFIX,ivi.ru,DIRECT
  - DOMAIN-SUFFIX,okko.tv,DIRECT
  - DOMAIN-SUFFIX,start.ru,DIRECT
  - DOMAIN-SUFFIX,more.tv,DIRECT
  - DOMAIN-SUFFIX,wink.rt.ru,DIRECT
  - DOMAIN-SUFFIX,premier.one,DIRECT
  - DOMAIN-SUFFIX,gpm_tv.ru,DIRECT

  - DOMAIN-SUFFIX,tass.ru,DIRECT
  - DOMAIN-SUFFIX,ria.ru,DIRECT
  - DOMAIN-SUFFIX,interfax.ru,DIRECT
  - DOMAIN-SUFFIX,rbc.ru,DIRECT
  - DOMAIN-SUFFIX,kommersant.ru,DIRECT
  - DOMAIN-SUFFIX,lenta.ru,DIRECT
  - DOMAIN-SUFFIX,gazeta.ru,DIRECT
  - DOMAIN-SUFFIX,iz.ru,DIRECT
  - DOMAIN-SUFFIX,rt.com,DIRECT
  - DOMAIN-SUFFIX,rg.ru,DIRECT
  - DOMAIN-SUFFIX,aif.ru,DIRECT

  - DOMAIN-SUFFIX,reg.ru,DIRECT
  - DOMAIN-SUFFIX,nic.ru,DIRECT
  - DOMAIN-SUFFIX,timepad.ru,DIRECT

  - RULE-SET,microsoft,DIRECT

  - RULE-SET,ru-bundle,DIRECT

  - GEOIP,RU,DIRECT

  - MATCH,🌐 Internet