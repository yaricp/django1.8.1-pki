client
dev {{ dev }}
proto {{ proto }}
sndbuf 0
rcvbuf 0
{% for c in servers %}
remote {{ c }} {{ port }}
{% endfor %}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher {{ cipher }}
{% if lzo %}
comp-lzo
{% endif %}
key-direction 1
verb 3
script-security 2
setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
up /etc/openvpn/update-systemd-resolved
down /etc/openvpn/update-systemd-resolved
down-pre

<key>
{{ key }}
</key>

<cert>
{{ pem }}
</cert>

<ca>
{{ ca }}
</ca>

<tls-auth>
{{ ta }}
</tls-auth>

