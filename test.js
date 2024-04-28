const qnd = require(".");

qnd.listen((channelIdentifier, message) => {
  console.log(`JavaScript: Channel #${channelIdentifier} says '${message}'`);
}, (sendHandle) => {
  setInterval(() => {
    sendHandle(1, `PING@${new Date()}`);
  })
});
