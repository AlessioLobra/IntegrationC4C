const cds = require('@sap/cds');

cds.on('bootstrap', app => {
  // Nessuna rotta pubblica: tutto passa per auth CAP
  // Se servono health checks pubblici, aggiungere qui eccezioni mirate.
});

module.exports = cds.server;