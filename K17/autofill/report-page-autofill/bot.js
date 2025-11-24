const puppeteer = require('puppeteer');
const fs = require('fs/promises');
const net = require('net');
const { randomUUID } = require('crypto');

const DOMAIN = process.env.DOMAIN;
if (DOMAIN == undefined) throw 'domain undefined'
const REGISTERED_DOMAIN = process.env.REGISTERED_DOMAIN;
const BLOCK_SUBORIGINS = process.env.BLOCK_SUBORIGINS == "1";
const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 20 * 1000;

// will only be used if BLOCK_SUBORIGINS is enabled
const PAC_B64 = Buffer.from(`
function FindProxyForURL (url, host) {
  if (host == "${DOMAIN}") {
    return 'DIRECT';
  }
  if (host == "${REGISTERED_DOMAIN}" || dnsDomainIs(host, ".${REGISTERED_DOMAIN}")) {
    return 'PROXY 127.0.0.1:1';
  }
  return 'DIRECT';
}
`).toString('base64');

(async function () {
  const data_path = `/tmp/chrome-profile-${randomUUID()}`;
  await fs.cp("/chrome-profile", data_path, {recursive: true});

  const puppeteer_args = {
    args: [`--user-data-dir=${data_path}`]
  };
  if (BLOCK_SUBORIGINS) {
    puppeteer_args.headless = false;
    puppeteer_args.args = [
      `--user-data-dir=${data_path}`,
      '--breakpad-dump-location=/tmp/chrome-crashes',
      '--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,' + PAC_B64,
    ];
  }
  
  const browser = await puppeteer.launch(puppeteer_args);

  function ask_for_url(socket) {
    socket.state = 'URL';
    socket.write('Please send the malicious URL for your colleague to open. You can assume that they will interact with the page one second after it loads.\n');
  }

  async function load_url(socket, data) {
    let url = data.toString().trim();
    console.log(`checking url: ${url}`);
    if (!url.startsWith(`https://${DOMAIN}/`)) {
      socket.state = 'ERROR';
      socket.write(`URL must start with https://${DOMAIN}/\n`);
      socket.destroy();
      return;
    }
    socket.state = 'LOADED';
    socket.write(`Loading ${url}\n`);

    const context = browser;
    const page = await context.newPage();

    setTimeout(()=>{
      try {
        context.close();
        socket.write('timeout\n');
        socket.destroy();
      } catch (err) {
        console.log(`err: ${err}`);
      }
    }, BOT_TIMEOUT);
  
    await page.goto(url);

    socket.write(`Page loaded...\n`);
    setTimeout(async () => {
      await page.mouse.click(0, 0);
      socket.write(`Interacted with the page.\n`);
    }, 1000);
  }

  var server = net.createServer();
  server.listen(1338);
  console.log('listening on port 1338');

  server.on('connection', socket => {
    socket.on('data', data => {
      try {
        if (socket.state == 'URL') {
          load_url(socket, data);
        }
      } catch (err) {
        console.log(`err: ${err}`);
      }
    });

    try {
      ask_for_url(socket);
    } catch (err) {
      console.log(`err: ${err}`);
    }
  });
})();

