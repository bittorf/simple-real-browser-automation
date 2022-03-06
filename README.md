### Usage

```
./boot-vm.sh	# needs ~3 sec till port 10080 is yours!

curl "http://127.0.0.1:10080/loadurl=http://c64.de"
curl "http://127.0.0.1:10080/screenshot=jpg"
curl "http://127.0.0.1:10080/action=report"
```

outputs a JSON like:
```
{
  "status": "success",
  "time_unix": 1643808355,
  "time_date": "Wed Feb  2 14:25:55 CET 2022 CET-1CEST,M3.5.0,M10.5.0/3",
  "url_userinput": "http://c64.de",
  "url_effective": "https://icomp.de/shop-icomp/en/news.html",
  "http_accept_language": "en-US,en;q=0.5",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8)",
  "download_time_ms": 2380,
  "download_size_bytes": 510237,
  "network_public_ip": "185.97.181.129",
  "network_country": "Germany",
  "network_action": [
    {"tims_ms":   20, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  130, "bytes_down":   2076, "bytes_up":   9555},
    {"tims_ms":  230, "bytes_down":   6802, "bytes_up":   2128},
    {"tims_ms":  330, "bytes_down":   1343, "bytes_up":   1446},
    {"tims_ms":  430, "bytes_down":   1343, "bytes_up":   1291},
    {"tims_ms":  530, "bytes_down":    184, "bytes_up":    346},
    {"tims_ms":  640, "bytes_down":   8282, "bytes_up":    797},
    {"tims_ms":  740, "bytes_down":   3720, "bytes_up":   1297},
    {"tims_ms":  850, "bytes_down":    732, "bytes_up":   1609},
    {"tims_ms":  960, "bytes_down":    205, "bytes_up":    100},
    {"tims_ms": 1070, "bytes_down":    428, "bytes_up":    512},
    {"tims_ms": 1190, "bytes_down":  22427, "bytes_up":  14549},
    {"tims_ms": 1300, "bytes_down": 112978, "bytes_up":   6702},
    {"tims_ms": 1400, "bytes_down":  48929, "bytes_up":   3994},
    {"tims_ms": 1510, "bytes_down": 276035, "bytes_up":   7668},
    {"tims_ms": 1630, "bytes_down":  18361, "bytes_up":  76433},
    {"tims_ms": 1770, "bytes_down":   1884, "bytes_up":  17347},
    {"tims_ms": 1870, "bytes_down":    976, "bytes_up":  16633},
    {"tims_ms": 1970, "bytes_down":   1520, "bytes_up":  24645},
    {"tims_ms": 2070, "bytes_down":   1276, "bytes_up":  18329},
    {"tims_ms": 2180, "bytes_down":    552, "bytes_up":   1049},
    {"tims_ms": 2280, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 2380, "bytes_down":    184, "bytes_up":    303}],
  "browser_version": "Mozilla Firefox 78.3.0esr",
  "resolution": "1280x720",
  "screenshot_size": 37744,
  "screenshot_format": "jpg",
  "screenshot_base64": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACAWC....."
}
```

There is more help:
```
curl "http://127.0.0.1:10080/help
```

You can view screenshots using base64-decoder and 'feh' like this:
```
curl "http://127.0.0.1:10080/action=report" | jq -r .screenshot_base64 | base64 -d | feh -
```

You can connect via VNC like this:
```
curl "http://127.0.0.1:10080/action=startvnc"
vncviewer 127.0.0.1:10059
or e.g.
xtightvncviewer -viewonly 127.0.0.1:10059
```


### Roadmap:

* TODO: https://zipcon.net/~swhite/docs/computers/browsers/fonttest.html
* TODO: https://get.webgl.org/
* TODO: force geolocation and dont prompt when asked to query?
* TODO: allow microphone (=file.wav) + camera (=stream.http or akvcam?) + e.g. jitsi-login
* TODO: cleancache
* TODO: netflix login
* TODO: https://github.com/angrykoala/awesome-browser-automation
* TODO: Cache-Control: no-cache ??? https://developer.mozilla.org/de/docs/Web/HTTP/Headers/Cache-Control
