const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require('fs');

const app = express();
const PORT = 3000;

const users = JSON.parse(fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8'));

// middleware
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
    res.cookie("info", "the flag isn't in anyone's cookie for this challenge", {
        httpOnly: false, // cookie can be read by client JS (you can set true if you want it hidden)
        sameSite: "Lax",
    });
    next();
});

// serve static files
app.use(express.static(path.join(__dirname, "public")));

// login route
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (users.find(user => user.username === username).password === password) {
        return res.redirect("/config.html");
    } else {
        return res.redirect("/login.html?error=1");
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
