"use strict";
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const app = express();
const flag = {};
const JWT_key = "HFPSREUKTDAOVJIQLNBGCWYZMX";

app.set("view engine", "ejs");
app.use(express.static("./public"));
app.use(express.urlencoded({ extended: true }));
// Accept json
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  let userOpinions = undefined;
  if (req.cookies["jwt"]) {
    userOpinions = jwt.verify(req.cookies.jwt, JWT_key).opinion;
    if (userOpinions.length > 10) {
      userOpinions.pop();
    }
  }
  res.render("index", { userOpinions });
});

app.post("/", (req, res) => {
  let temp = validate(req.body);
  let userOpinions = [];

  temp["opinion"] = temp["opinion"].trim();
  if (temp.valid && temp["opinion"].length) 
    userOpinions.push(temp["opinion"]);

  if (req.cookies["jwt"]) {
    let pastOpinion = jwt.verify(req.cookies.jwt, JWT_key).opinion;
    userOpinions = userOpinions.concat(pastOpinion);
    if (userOpinions.length > 10) {
      userOpinions.pop();
    }
  }
  let newToken = jwt.sign({ opinion: userOpinions }, JWT_key);
  res.cookie("jwt", newToken, {httpOnly: true, sameSite: "None", secure: true});

  if (userOpinions && flag.flag === true) {
    if (temp.flag === true) {
      userOpinions.push("Please, no hack!");
      res.render("index", { userOpinions });
    } else {
      userOpinions.push(process.env.FLAG || "Flag{lmaolmao}");
      res.render("index", { userOpinions });
    }
  } else {
    res.render("index", { userOpinions });
  }
  process.exit(0);
});

function validate(opinion) {
  let temp = {
    valid: true
  }
  let regex = /[_a-zA-Z][_a-zA-Z0-9]*/;
  for(let k in opinion) {
    if(!regex.test(k)) {
      delete opinion[k];
      temp.valid = false;
    } 
  }
  merge(temp, opinion);
  return temp;
}


function merge(target, source) {
  for (const key in source) {
    if (typeof target[key] === "object" && typeof source[key] === "object") {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

app.listen(process.env.PORT || 5000);
