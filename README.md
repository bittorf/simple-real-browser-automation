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
  "time_unix": 1646562002,
  "time_date": "Sun Mar  6 11:20:02 CET 2022 CET-1CEST,M3.5.0,M10.5.0/3",
  "url_userinput": "http://hackernews.com",
  "url_effective": "https://news.ycombinator.com/",
  "https_valid_certificate": true,
  "http_accept_language": "en-US,en;q=0.5",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
  "browser_version": "Mozilla Firefox 91.6.1esr",
  "download_time_ms": 1520,
  "download_size_bytes": 31766,
  "network_public_ip": "178.19.227.165",
  "network_country": "Germany",
  "network_action": [
    {"tims_ms":   40, "bytes_down":    436, "bytes_up":    296},
    {"tims_ms":  150, "bytes_down":    791, "bytes_up":    793},
    {"tims_ms":  250, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  350, "bytes_down":    120, "bytes_up":    631},
    {"tims_ms":  460, "bytes_down":   4108, "bytes_up":    120},
    {"tims_ms":  570, "bytes_down":    120, "bytes_up":    692},
    {"tims_ms":  670, "bytes_down":   7061, "bytes_up":    180},
    {"tims_ms":  780, "bytes_down":   2528, "bytes_up":   2324},
    {"tims_ms":  890, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  990, "bytes_down":   2942, "bytes_up":   2828},
    {"tims_ms": 1100, "bytes_down":   2530, "bytes_up":    547},
    {"tims_ms": 1200, "bytes_down":   1050, "bytes_up":   2088},
    {"tims_ms": 1300, "bytes_down":   1483, "bytes_up":    180},
    {"tims_ms": 1420, "bytes_down":    330, "bytes_up":    621},
    {"tims_ms": 1520, "bytes_down":   8267, "bytes_up":    120}],
  "resolution": "1280x720",
  "screenshot_filesize": 59490,
  "screenshot_mime": "image/jpeg",
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
curl "http://127.0.0.1:10080/screenshot=jpg"
curl "http://127.0.0.1:10080/action=report" | jq -r .screenshot_base64 | base64 -d | feh -
```

You can connect via VNC like this:
```
curl "http://127.0.0.1:10080/action=startvnc"
vncviewer 127.0.0.1:10059
or e.g.
xtightvncviewer -viewonly 127.0.0.1:10059
```

For tunneling the traffic through another box you can  
upload your private SSH key to the VM and start sshuttle:  
```
curl "http://127.0.0.1:10080/sshprivkey=$( base64 -w0 ~/.ssh/id_rsa )"
curl "http://127.0.0.1:10080/sshuttle=user@any.remote.box"
```

### Why?

* anti bot undetectable and scalable scraping infrastructure: https://abrahamjuliot.github.io/creepjs/


### Roadmap:

* TODO: https://zipcon.net/~swhite/docs/computers/browsers/fonttest.html
* TODO: better readiness test like https://gtmetrix.com/
* TODO: force geolocation and dont prompt when asked to query?
* TODO: allow microphone (=file.wav) + camera (=stream.http or akvcam?) + e.g. jitsi-login
* TODO: cleancache
* TODO: netflix login
* TODO: https://github.com/angrykoala/awesome-browser-automation
* TODO: Cache-Control: no-cache ??? https://developer.mozilla.org/de/docs/Web/HTTP/Headers/Cache-Control
