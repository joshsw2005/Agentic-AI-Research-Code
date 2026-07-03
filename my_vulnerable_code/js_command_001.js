const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});
