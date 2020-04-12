# turnproxy

[![Python 3](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](https://github.com/trichimtrich/turnproxy/blob/master/LICENSE)

> `turn` ~server~ into something you can `see` through

a small script that

- tests TCP connectivity between your turn-server and any peer-destination
- uses your turn-server as TCP proxy with SOCKS interface

## usage

```
➜ python turnproxy.py --help
usage: turnproxy command

test your turn-server tcp relay and use it as a proxy with socks interface

optional arguments:
  -h, --help  show this help message and exit

command:

    test      ask turn server to create a tcp connection to your peer host
    run       run a socks proxy via your turn server
```

- test connection to good peer `8.8.8.8:53`

```
➜ python turnproxy.py test -t <turn_host>:<turn_port> -u username -p password -c 8.8.8.8:53
Turn server == <turn_host>:<turn_port>
Connecting to peer --> 8.8.8.8:53
Connection OK
```

- test connection to bad peer `8.8.8.8:54`

```
➜ python turnproxy.py test -t <turn_host>:<turn_port> -u username -p password -c 8.8.8.8:54
Turn server == <turn_host>:<turn_port>
Connecting to peer --> 8.8.8.8:53
Error 447: b'Connection Timeout or Failure\x00\x00\x00'
```

- listen on `127.0.0.1:9999` as SOCKS proxy

```
➜ python turnproxy.py run -t <turn_host>:<turn_port> -u username -p password -s 127.0.0.1:9999
Turn server == <turn_host>:<turn_port>
Socks server listening <-- 127.0.0.1:9999
127.0.0.1:2330 - Connected
127.0.0.1:2330 - SOCKS established
127.0.0.1:2330 - Client disconnected
127.0.0.1:2335 - Connected
...
```

- config socks proxy for your `http`, `ssh`, `redis`, `mysql`, ... clients and enjoy 😉

- enable flag `-d` or `--debug` if you are curious

## docs

this work is heavily inspired from the awesome disclosure below

- https://www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise/

## qa

what is `turn` ?

- https://tools.ietf.org/html/rfc5766

then, what is `stun` ?

- https://tools.ietf.org/html/rfc5389
- https://tools.ietf.org/html/rfc3489

where they are used ?

- https://webrtc.org/
- https://en.wikipedia.org/wiki/Session_Initiation_Protocol

i mean where?

- http://messenger.com/
- https://discordapp.com/
- https://slack.com/
- http://cloudretro.io/

thats too much info, i just want to test this script

- https://meetrix.io/blog/webrtc/coturn/installation.html