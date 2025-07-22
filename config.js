
// Konfigurasi Pterodactyl Panel
// File ini bisa di-obfuscate atau menggunakan environment variables

const PANEL_CONFIG = {
  url: process.env.PTERODACTYL_URL || 'https://panel.example.com',
  apiKey: process.env.PTERODACTYL_API_KEY || 'plta_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  nodeId: parseInt(process.env.PTERODACTYL_NODE_ID) || 1,
  eggId: parseInt(process.env.PTERODACTYL_EGG_ID) || 15,
  locationId: parseInt(process.env.PTERODACTYL_LOCATION_ID) || 1,
  dockerImage: process.env.PTERODACTYL_DOCKER_IMAGE || 'ghcr.io/parkervcp/yolks:nodejs_18',
  environment: {
    STARTUP: process.env.PTERODACTYL_STARTUP || 'if [[ -d .git ]] && [[ {{AUTO_UPDATE}} == "1" ]]; then git pull; fi; if [[ ! -z ${NODE_PACKAGES} ]]; then /usr/local/bin/npm install ${NODE_PACKAGES}; fi; if [[ ! -z ${UNNODE_PACKAGES} ]]; then /usr/local/bin/npm uninstall ${UNNODE_PACKAGES}; fi; if [ -f /home/container/package.json ]; then /usr/local/bin/npm install; fi; /usr/local/bin/node /home/container/{{BOT_JS_FILE}}',
    P_SERVER_LOCATION: 'test',
    P_SERVER_UUID: '',
    BOT_JS_FILE: 'index.js',
    AUTO_UPDATE: '0',
    NODE_PACKAGES: '',
    UNNODE_PACKAGES: ''
  }
};

module.exports = PANEL_CONFIG;
