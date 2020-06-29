const APP_ID = "b9eaa596-9fe3-43c1-a802-b8023a820dd3";
const APP_SECERET = "IrgLM72Jx-_mR]fM=ydzEQBTGLtnyJ33";
const TOKEN_ENDPOINT =
  "https://login.microsoftonline.com/850911a1-03a0-4fc8-84a9-180a47a49d6d/oauth2/v2.0/token";
const MS_GRAPH_SCOPE = "User.Read";
const GRAPH_API = "https://graph.microsoft.com/v1.0/me";

const axios = require("axios");
const qs = require("qs");
const GeoIP = require("simple-geoip");

var json2csv = require("json2csv").parse;
var express = require("express");
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");
var fs = require("fs");
var csv = require("csvtojson");
const Speakeasy = require("speakeasy");
const nodemailer = require("nodemailer");
var http = require("http");

var infosClients = 0;
var mail_token;

http.get("http://bot.whatismyipaddress.com", function (res) {
  res.setEncoding("utf8");
  res.on("data", function (chunk) {
    let geoIP = new GeoIP(" at_nwugRw0KmovOetEPhi5lbQFrVowvj");
    geoIP.lookup(chunk, (err, data) => {
      if (err) throw err;
      infosClients = data;
    });
  });
});

var app = express();

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);

app.use(express.static(__dirname));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get("/", function (request, response) {
  response.sendFile(path.join(__dirname + "/login.html"));
});

app.post("/auth", function (request, response) {
  var user = request.body.username;
  var passw = request.body.password;

  let postData = {
    client_id: APP_ID,
    scope: MS_GRAPH_SCOPE,
    client_secret: APP_SECERET,
    username: user,
    password: passw,
    grant_type: "password",
  };

  if (user && passw) {
    const converter = csv()
      .fromFile("./Database/T_VERIFICATION.csv")
      .then((comptes) => {
        var bloqued = "0";
        for (let compte of comptes) {
          if (compte.ip == infosClients.ip) {
            bloqued = compte.bloqued;
          }
        }
        if (bloqued == "1") {
          fs.readFile("login.html", "utf8", function (err, data) {
            if (err) {
              return console.log(err);
            }
            var toPrepand =
              "<h3> Votre adresse IP est bloquée à cause d'un nombre de tentative échouée trop élevé </h3>";
            data = data + toPrepand;
            response.send(data);
            //console.log(data);
          });
        } else {
          axios.defaults.headers.post["Content-Type"] =
            "application/x-www-form-urlencoded";

          axios
            .post(TOKEN_ENDPOINT, qs.stringify(postData))
            .then((res) => {
              const converter = csv()
                .fromFile("./Database/T_COMPROMIS.csv")
                .then((comptes) => {
                  var compromis = false;
                  for (let compte of comptes) {
                    if (compte.compte == user && compte.password == passw) {
                      compromis = true;
                    }
                  }
                  if (compromis == true) {
                    fs.readFile("login.html", "utf8", function (
                      err,
                      data
                    ) {
                      if (err) {
                        return console.log(err);
                      }
                      var toPrepand =
                        "<h3> Votre compte à été hacké.Contactez votre administrateur </h3>";
                      data = data + toPrepand;
                      response.send(data);
                      //console.log(data);
                    });
                  } else {
                    let access_token = "Bearer " + res.data["access_token"];
                    let config = {
                      headers: {
                        Authorization: access_token,
                      },
                    };
                    axios
                      .get(GRAPH_API, config)
                      .then((res) => {
                        infos_comptes = res.data;
                        //console.log(infos_comptes)
                        request.session.loggedin = true;
                        request.session.infos = infos_comptes;
                        response.redirect("totp.html");
                        response.end();
                      })
                      .catch((error) => {
                        console.log(error);
                        response.send("Le jeton n'est pas valide");
                      });
                  }
                });
            })
            .catch((error) => {
              //console.log(error);
              fs.readFile("login.html", "utf8", function (
                err,
                data
              ) {
                if (err) {
                  return console.log(err);
                }
                console.log(infosClients.ip)
                const converter = csv()
                  .fromFile("./Database/T_VERIFICATION.csv")
                  .then((comptes) => {
                    if (comptes.length == 0) {
                      var appendThis = {
                        Compte: user,
                        ip: infosClients.ip,
                        failed: 1,
                        bloqued: 0,
                      };
                      //write the actual data and end with newline
                      var csv = json2csv(appendThis) + "\r\n";
                      fs.writeFile(
                        "./Database/T_VERIFICATION.csv",
                        csv,
                        function (err) {
                          if (err) throw err;
                          console.log(
                            'The "data to append" was appended to file!'
                          );
                        }
                      );
                    } else {
                      let l_comptes = [];
                      var appendThis = {
                        Compte: user,
                        ip: infosClients.ip,
                        failed: "1",
                        bloqued: "0",
                      };
                      for (var compte of comptes) {
                        if (compte.ip == infosClients.ip) {
                          var failed = compte.failed;
                          if(failed > 9){
                            appendThis = {
                              Compte: user,
                              ip: infosClients.ip,
                              failed: (parseInt(failed) + 1).toString(),
                              bloqued: "1",
                            };
                          } else {
                            appendThis = {
                              Compte: user,
                              ip: infosClients.ip,
                              failed: (parseInt(failed) + 1).toString(),
                              bloqued: "0",
                            };
                          }
                          
                        } else l_comptes.push(compte);
                      }
                      l_comptes.push(appendThis);

                      //write the actual data and end with newline
                      var csv = json2csv(l_comptes) + "\r\n";
                      fs.writeFile(
                        "./Database/T_VERIFICATION.csv",
                        csv,
                        function (err) {
                          if (err) throw err;
                          console.log(
                            'The "data to append" was appended to file!'
                          );
                        }
                      );
                    }
                  })
                  .catch((err) => {
                    print("erreur at T_Verification")
                  });

                var toPrepand =
                  "<h3> Les identifiants saisis ne sont pas valides </h3>";
                data = data + toPrepand;
                response.send(data);
                //console.log(data);
              });
            });
        }
      });
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

app.post("/totp-validate", function (request, response) {
  require("crypto").randomBytes(48, function (ex, buf) {
    mail_token = buf.toString("base64").replace(/\//g, "_").replace(/\+/g, "-");
  });

  let lesecret = "";
  //GET IP ADRESSES OF THE LOCAL MACHINE
  var os = require("os");

  var interfaces = os.networkInterfaces();
  var addresses = [];
  for (var k in interfaces) {
    for (var k2 in interfaces[k]) {
      var address = interfaces[k][k2];
      if (address.family === "IPv4" && !address.internal) {
        addresses.push(address.address);
      }
    }
  }

  console.log(addresses);

  //Configure Mail Server

  let transport = nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "ee0cf3e8c15455",
      pass: "726b8dd1eff9d8",
    },
  });

  const converter = csv()
    .fromFile("./Database/T_INFOSCOMPTES.csv")
    .then((comptes) => {
      for (const compte of comptes) {
        if (compte["email"] == request.session.infos["userPrincipalName"]) {
          lesecret = compte["Secret"];
          request.session.navigateur = compte["Navigateur"];
          request.session.ip = compte["IP"];
          console.log(lesecret);
        }
      }

      totp = Speakeasy.totp({
        secret: lesecret,
        encoding: "base32",
      });

      if (request.body.Code == totp) {
        if ("FR" != "FR") {
          response.send("/confirm.html");
          const url = `http://localhost:3000/confirm/${mail_token}`;
          const message = {
            from: "no-replay@chatelet.com", // Sender address
            to: "to@email.com", // List of recipients
            subject: "Alerte Connexion depuis l`etranger", // Subject line
            text:
              "Bonjour " +
              request.session.infos["displayName"] +
              ", Confirmez votre connexion " +
              url, // Plain text body
          };
          transport.sendMail(message, function (err, info) {
            if (err) {
              console.log(err);
            } else {
              console.log("email envoyé");
            }
          });
        } else {
          console.log(request.session.navigateur)
          useragent = request.headers["user-agent"];
          let Nom = request.session.infos["displayName"];
          if (
            useragent.includes(request.session.navigateur) &&
            addresses.includes(request.session.ip)
          ) {
            response.redirect("/home");
          } else if (!useragent.includes(request.session.navigateur)) {
            response.send("/confirm.html");
            const url = `http://localhost:3000/confirm/${mail_token}`;
            const message = {
              from: "no-replay@chatelet.com", // Sender address
              to: "to@email.com", // List of recipients
              subject: "Alerte Connexion depuis un navigateur différent", // Subject line
              text:
                "Bonjour " +
                request.session.infos["displayName"] +
                ", Confirmez votre connexion " +
                url, // Plain text body
            };
            transport.sendMail(message, function (err, info) {
              if (err) {
                console.log(err);
              } else {
                console.log("email envoyé");
              }
            });
          } else {
            response.redirect("/home");
            const message = {
              from: "no-replay@chatelet.com", // Sender address
              to: "to@email.com", // List of recipients
              subject: "Alerte Connexion", // Subject line
              text:
                "Bonjour " +
                Nom +
                ", nous avons remarqué une connexion depuis une adresse IP différente", // Plain text body
            };
            transport.sendMail(message, function (err, info) {
              if (err) {
                console.log("Il ya eu un problème lors de l`envoi du mail ");
              } else {
                console.log("email envoyé");
              }
            });
          }
        }
      } else {
        fs.readFile("totp.html", "utf8", function (err, data) {
          if (err) {
            return console.log(err);
          }
          var toPrepand = "<h3> Le code saisi n'est pas correct </h3>";
          data = data + toPrepand;
          response.send(data);
          //console.log(data);
        });
      }
    });
});

app.get("/home", function (request, response) {
  let Nom = request.session.infos["displayName"];

  response.send("Bonjour " + Nom);
});

app.get("/confirm/:token", function (request, response) {
  if (request.params.token == mail_token) {
    response.redirect("/home");
    mail_token = 0;
  }
  else {
    response.send("404")
  }
  //response.send("Pays étranger")
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Started on PORT 3000");
});

function getUsers(token) {
  let config = {
    headers: {
      Authorization: token,
    },
  };

  axios
    .get(GRAPH_API, config)
    .then((response) => {
      //console.log(response.data)
      infos_comptes = response.data;
    })
    .catch((error) => {
      infos_comptes = "erreur";
    });
}
