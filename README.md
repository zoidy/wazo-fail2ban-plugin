This fork fixes an issue when running the web frontend to include the port number in the API request URL. It also updates some dependencies to the later versions (not the latest since substantial code changes would be needed to update them to the latest) 

Fail2ban for Wazo
----------
  
Fail2Ban operates by monitoring log files (e.g. `/var/log/auth.log`, `/var/log/apache/access.log`, etc.) for selected entries and running scripts based on them. Most commonly this is used to block selected IP addresses that may belong to hosts that are trying to breach the system's security.

**What is fail2ban for Wazo?**  
Frontend (vuejs) and backend (fastapi). FastAPI retrieves its data from the socket files created by Fail2ban.

![Fail2ban Wazo Demo](./screenshots/wazo-fail2ban.png?raw=true)

## To launch the plugin

Clone rep, install docker and docker-compose.
```bash
git clone https://github.com/zoidy/wazo-fail2ban-plugin
```

To build the image
```bash
docker compose -f docker-compose.yaml -f docker-compose.dev.yaml build
```

To launch the project
```bash
docker compose up -d
```

To add the plugin inside Wazo portal add https://\<dns\>/manifest-portal.json

Please note, https is mandatory and valid certificate is better.

**THIS IS A PROOF OF CONCEPT DON'T USE IT IN PRODUCTION**
