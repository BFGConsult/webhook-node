// Require express and body-parser
const crypto = require('crypto')
const express = require("express")
const bodyParser = require("body-parser")
const { exec } = require("child_process");
const {transports, createLogger, format} = require('winston')

// Initialize express and define a port
const app = express()
const fs = require('fs');

let rawdata = fs.readFileSync('config.json');
let config = JSON.parse(rawdata);

const transport = ("logFile" in config) ?
  new transports.File({filename: config.logFile, level:'info'}) :
  new transports.Console()

const myWinstonOptions = {
    format: format.combine(
            format.timestamp(),
            format.json()
        ),
    transports: [transport]
}
const logger = new createLogger(myWinstonOptions)

const sigHeaderName = 'X-Hub-Signature-256'
const sigHashAlg = 'sha256'
const cmdDefault = 'git pull'

const internal_map = config.repoMap
const PORT = config.port
const secret = config.secret

// Start express on the defined port
app.listen(PORT, () => logger.info(`🚀 Server running on port ${PORT}`))

app.use(bodyParser.json({
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  },
}))

app.post("/hook", verifyPostData, function (req, res) {
  body=req.body
  reponame=body.repository.full_name
  if (!(reponame in internal_map) ) {
    res.status(403).end()
    return
  }
  repoConfig=internal_map[reponame]
  cmd=""
  if (typeof repoConfig === 'string' ) {
    repoPath=repoConfig
    cmd=cmdDefault
  }
  else {
    repoPath=repoConfig['repoPath']
    cmd = repoConfig['cmd'] || cmdDefault;
  }
  logger.info(reponame + " => " + JSON.stringify(repoConfig))
  logger.info("CMD:" + cmd)

  process.chdir(repoPath)
  if (!execute(cmd)) {
    res.status(500).end()
    return;
  }
  res.status(200).end()
})

function execute(cmd) {
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
        logger.error(`error: ${error.message}`);
        return false;
    }
    if (stderr) {
        logger.error(`stderr: ${stderr}`);
        return true;
    }
    logger.info(`stdout: ${stdout}`);
  });
  return true;
}

function verifyPostData(req, res, next) {
  if (!req.rawBody) {
    return next('Request body empty')
  }

  const sig = Buffer.from(req.get(sigHeaderName) || '', 'utf8')
  const hmac = crypto.createHmac(sigHashAlg, secret)
  const digest = Buffer.from(sigHashAlg + '=' + hmac.update(req.rawBody).digest('hex'), 'utf8')
  if (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig)) {
    return next(`Request body digest (${digest}) did not match ${sigHeaderName} (${sig})`)
  }

  return next()
}
