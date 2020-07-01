//Informations permettant l'utilisation de l'API MS Graph, afin d'accéder à L'AzureAD

const APP_ID = "b9eaa596-9fe3-43c1-a802-b8023a820dd3";
const APP_SECERET = "IrgLM72Jx-_mR]fM=ydzEQBTGLtnyJ33";
const TOKEN_ENDPOINT =
  "https://login.microsoftonline.com/850911a1-03a0-4fc8-84a9-180a47a49d6d/oauth2/v2.0/token";
const MS_GRAPH_SCOPE = "User.Read";
const GRAPH_API = "https://graph.microsoft.com/v1.0/me";

//Modules
const axios = require("axios");//Requêtes post/get
const qs = require("qs");
const GeoIP = require("simple-geoip");//Informations de geolocalisation à partir d'une adresse IP
var json2csv = require("json2csv").parse;//JSON to CSV
var express = require("express");//Application Web (routes)
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");//Permet de connaitre le chemin absolu de l'app
var fs = require("fs");//Lecture de fichiers
var csv = require("csvtojson");// CSV to JSON
const Speakeasy = require("speakeasy");//Permet de vérifier la clé secrète du OTP
const nodemailer = require("nodemailer");//Envoyer des mails
var http = require("http");//requetes http

var infosClients = 0;
var mail_token;
var ipAddr;
var isconnected = false;

var app = express();

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);

app.use(express.static(__dirname));//Défini le repertoire courant (pour les chemins relatifs)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//Page de login "/"
app.get("/", function (request, response) {
  response.sendFile(path.join(__dirname + "/login.html"));//Envoie le contenu du fichier login.html
  ipAddr = request.headers["x-forwarded-for"];//Récupère les adresses IP du poste client
  if (ipAddr) {
    var list = ipAddr.split(",");
    console.log(list);
    ipAddr = list[0];//L'addresse IP qui nous interesse est la première de la liste
  } else {
    ipAddr = request.connection.remoteAddress;
  }

  http.get("http://bot.whatismyipaddress.com", function (res) {
    res.setEncoding("utf8");
    res.on("data", function (chunk) {
      //On récupère les données de localisations correspondant à l'adresse IP
      let geoIP = new GeoIP(" at_nwugRw0KmovOetEPhi5lbQFrVowvj");
      geoIP.lookup(ipAddr, (err, data) => {
        if (err) throw err;
        infosClients = data;
      });
    });
  });
});

//Route de vérification : IP sur liste noire, identifiants compromis, Identifiants corrects
app.post("/auth", function (request, response) {
  ipAddr = request.headers["x-forwarded-for"];
  if (ipAddr) {
    var list = ipAddr.split(",");
    console.log(list);
    ipAddr = list[0];
  } else {
    ipAddr = request.connection.remoteAddress;
  }
  //On récupère les identifiants obtenu via le POST de la page login
  var user = request.body.username;
  var passw = request.body.password;

  //On prépare le Corps de la réquète vers MS Graph
  let postData = {
    client_id: APP_ID,
    scope: MS_GRAPH_SCOPE,
    client_secret: APP_SECERET,
    username: user,
    password: passw,
    grant_type: "password",
  };

  //On vérifie que des identifiants ont été saisis
  if (user && passw) {
    
    //Vérification de la liste noire
    const converter = csv()
      .fromFile("./Database/T_VERIFICATION.csv")
      .then((comptes) => {
        var bloqued = "0";
        //On cherche si l'IP du client se trouve sur la liste noire
        for (let compte of comptes) {
          if (compte.ip == ipAddr) {
            //Si l'IP est trouvée, on vérifie si elle est bannie
            bloqued = compte.bloqued;
          }
        }
        //Si elle est bannie, on bloque la connexion et on indique que l'IP est bannie
        if (bloqued == "1") {
          fs.readFile("login.html", "utf8", function (err, data) {
            if (err) {
              return console.log(err);
            }
            var toPrepand =
              "<h3> Votre adresse IP est sur liste noire à cause d'un nombre de tentative échouée trop élevé </h3>";
            data = data + toPrepand;
            response.send(data);
            //console.log(data);
          });
          //Si elle n'est pas bannie
        } else {
          //On vérifie si elle ne se trouve pas dans une base données avec mail et mdp rendus publics
          const converter = csv()
            .fromFile("./Database/T_COMPROMIS.csv")
            .then((comptes) => {
              var compromis = false;
              for (let compte of comptes) {
                //On cherche une occurence dans la base
                if (compte.compte == user || compte.password == passw) {
                  compromis = true;
                }
              }
              if (compromis == true) {
                //on bloque la connexion et on indique que les identifiants ont été hackés
                fs.readFile("login.html", "utf8", function (err, data) {
                  if (err) {
                    return console.log(err);
                  }
                  var toPrepand =
                    "<h3> Votre compte se trouve dans une base de donnée publique. La connexion à été refusée. </h3>";
                  data = data + toPrepand;
                  response.send(data);
                });
              } else {
                //Si les deux vérifications ont été passées...
                axios.defaults.headers.post["Content-Type"] =
                  "application/x-www-form-urlencoded";
                //On fait une réquète post vers l'ENDPOINT de Azure AD
                axios
                  .post(TOKEN_ENDPOINT, qs.stringify(postData))
                  .then((res) => {
                    //Si les identifiants sont corrects, on récupère un jeton de connexion
                    let access_token = "Bearer " + res.data["access_token"];
                    let config = {
                      headers: {
                        Authorization: access_token,
                      },
                    };
                    //Avec le jeton, on fait une requète get vers l'API MS GRAPH
                    axios
                      .get(GRAPH_API, config)
                      .then((res) => {
                        //Si le jeton est correct, l'API nous renvoie les informations du compte.
                        infos_comptes = res.data;
                        request.session.loggedin = true;
                        request.session.infos = infos_comptes;
                        response.redirect("/totp");
                        response.end();
                      })
                      .catch((error) => {
                        console.log(error);
                        response.send("Le jeton n'est pas valide");
                      });
                  })
                  .catch((error) => {
                    //Si les identifiants saisis ne sont pas valides...
                    fs.readFile("login.html", "utf8", function (err, data) {
                      if (err) {
                        return console.log(err);
                      }
                      console.log(ipAddr);
                      const converter = csv()
                        .fromFile("./Database/T_VERIFICATION.csv")
                        .then((comptes) => {
                          //On ajoute l'adresse IP du client à la liste noire.
                          //L'IP n'est pas tout de suite bloquée, mais le nombre d'essai et initialisé à 1
                          if (comptes.length == 0) {
                            var appendThis = {
                              Compte: user,
                              ip: ipAddr,
                              failed: 1,
                              bloqued: 0,
                            };
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
                              ip: ipAddr,
                              failed: "1",
                              bloqued: "0",
                            };
                            for (var compte of comptes) {
                              if (compte.ip == ipAddr) {
                                //Si l'IP se trouve déjà dans la liste noire, on incremente le nombre d'essai
                                var failed = compte.failed;
                                if (failed > 3) {
                                  //Si le nombre d'essai est superieur à 3, l'IP devient bloquée
                                  appendThis = {
                                    Compte: user,
                                    ip: ipAddr,
                                    failed: (parseInt(failed) + 1).toString(),
                                    bloqued: "1",
                                  };
                                } else {
                                  appendThis = {
                                    Compte: user,
                                    ip: ipAddr,
                                    failed: (parseInt(failed) + 1).toString(),
                                    bloqued: "0",
                                  };
                                }
                              } else l_comptes.push(compte);
                            }
                            l_comptes.push(appendThis);
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
                          print("erreur at T_Verification");
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
        }
      });
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

//Page du OTP
app.get("/totp", function (request, response) {
  if (request.session.infos != undefined) {
    response.sendFile(path.join(__dirname + "/totp.html"));
  } else {
    response.redirect("/");
  }
});

//Traitement du OTP
app.post("/totp-validate", function (request, response) {
  //On crée un jeton pour le mail de confirmation
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

  //Co,figuration du serveur de mail
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
        //On récupère les informations de l'utilisateur qui se connecte
        if (compte["email"] == request.session.infos["userPrincipalName"]) {
          lesecret = compte["Secret"];
          request.session.navigateur = compte["Navigateur"];
          request.session.ip = compte["IP"];
        }
      }

      //On recupère le OTP correspondant a l'utilisateur
      totp = Speakeasy.totp({
        secret: lesecret,
        encoding: "base32",
      });
      
      //On compare avec le OTP saisi
      if (request.body.Code == totp) {
        //Si le bon OTP est saisi on verifie le pays et le navigateur de puis lesquels on se connecte
        console.log(infosClients.location.country);
        if (infosClients.location.country != "FR") {
          response.send(`<!DOCTYPE html>
          <html>
            <head>
              <meta charset="utf-8">
              <title>Portail d'Authentification</title>
              <style>
              .login-form {
                width: 300px;
                margin: 0 auto;
                font-family: Tahoma, Geneva, sans-serif;
              }
              .login-form h1 {
                text-align: center;
                color: #4d4d4d;
                font-size: 24px;
                padding: 20px 0 20px 0;
              }
          
                  .login-form h2 {
                text-align: center;
              }
              .login-form input[type="password"],
              .login-form input[type="text"] {
                width: 100%;
                padding: 15px;
                border: 1px solid #dddddd;
                margin-bottom: 15px;
                box-sizing:border-box;
              }
              .login-form input[type="submit"] {
                width: 100%;
                padding: 15px;
                background-color: #535b63;
                border: 0;
                box-sizing: border-box;
                cursor: pointer;
                font-weight: bold;
                color: #ffffff;
              }
              </style>
            </head>
            <body>
              <div class="login-form">
                      <h1>Un mail a été envoyé, confirmez votre identité !</h1>
                      <h2>Nous avons détécté une connexion hors France métropolitaine (${infosClients.location.country})</h2>
              </div>
            </body>
          </html>`);
          const url =
            request.protocol +
            "://" +
            request.get("host") +
            "/confirm/" +
            mail_token;
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
          //On envoie un mail demandant la confirmation, avec un lien de confirmation
          transport.sendMail(message, function (err, info) {
            if (err) {
              console.log(err);
            } else {
              console.log("email envoyé");
            }
          });
        } else {
          console.log(request.session.navigateur);
          useragent = request.headers["user-agent"];//On récupère le bom du navigateur du client
          let Nom = request.session.infos["displayName"];
          //On compare le navigateur du client avec le navigateur associé au compte
          if (
            useragent.includes(request.session.navigateur) &&
            addresses.includes(request.session.ip)
          ) {
            //On redirige vers la page d'acceuil et isconnected devient true
            isconnected = true
            response.redirect("/home");
          } else if (!useragent.includes(request.session.navigateur)) {
            //Si ce n'est pas le même navigateur
            console.log("Navigateur Différent \ntoken: " + mail_token)
            response.send(`<!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <title>Portail d'Authentification</title>
                <style>
                .login-form {
                  width: 300px;
                  margin: 0 auto;
                  font-family: Tahoma, Geneva, sans-serif;
                }
                .login-form h1 {
                  text-align: center;
                  color: #4d4d4d;
                  font-size: 24px;
                  padding: 20px 0 20px 0;
                }
            
                    .login-form h2 {
                  text-align: center;
                }
                .login-form input[type="password"],
                .login-form input[type="text"] {
                  width: 100%;
                  padding: 15px;
                  border: 1px solid #dddddd;
                  margin-bottom: 15px;
                  box-sizing:border-box;
                }
                .login-form input[type="submit"] {
                  width: 100%;
                  padding: 15px;
                  background-color: #535b63;
                  border: 0;
                  box-sizing: border-box;
                  cursor: pointer;
                  font-weight: bold;
                  color: #ffffff;
                }
                </style>
              </head>
              <body>
                <div class="login-form">
                        <h1>Un mail a été envoyé, confirmez votre identité !</h1>
                        <h2>Nous avons détécté une connexion depuis un navigateur différent</h2>
                </div>
              </body>
            </html>`);
            const url =
              request.protocol +
              "://" +
              request.get("host") +
              "/confirm/" +
              mail_token;
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
            //On envoie un mail avec un lien de confirmation
            transport.sendMail(message, function (err, info) {
              if (err) {
                console.log(err);
              } else {
                console.log("email envoyé");
              }
            });
          } else {
            //Si l'IP est différente, on redirige vres la page d'acceuil et isconnected devient true
            isconnected = true;
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
            //Mais on envoie quand même un mail indiquant une IP différente
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
        //Si le code saisi n'est pas correct
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

//Page d'accueil
app.get("/home", function (request, response) {
  //isconnected definit si l'utilisateur est connécté
  if (isconnected == true) {
    let Nom = request.session.infos["displayName"];
    response.send(`<!DOCTYPE html>
  <html>
    <head>
      <meta charset="utf-8">
      <title>Accueil</title>
      <style>
      .login-form {
        width: 300px;
        margin: 0 auto;
        font-family: Tahoma, Geneva, sans-serif;
      }
      .login-form h1 {
        text-align: center;
        color: #4d4d4d;
        font-size: 24px;
        padding: 20px 0 20px 0;
      }
  
          .login-form h2 {
        text-align: center;
      }
      .login-form input[type="password"],
      .login-form input[type="text"] {
        width: 100%;
        padding: 15px;
        border: 1px solid #dddddd;
        margin-bottom: 15px;
        box-sizing:border-box;
      }
      .login-form input[type="submit"] {
        width: 100%;
        padding: 15px;
        background-color: #535b63;
        border: 0;
        box-sizing: border-box;
        cursor: pointer;
        font-weight: bold;
        color: #ffffff;
      }
      </style>
    </head>
    <body>
      <div class="login-form">
              <h1>Bienvenue !</h1>
              <h2>Comment allez vous, ${Nom} ?</h2>
          <form action="logout" method="POST">
				      <input type="submit" value="Se deconnecter">
			  </form>
      </div>
    </body>
  </html>`);
  } else {
    response.redirect("/");
  }
});

//Page de confirmation avec comme paramètre le mail_token
app.get("/confirm/:token", function (request, response) {
  //Si le token en paramètre correspond à celui envoyé par mail
  if (request.params.token == mail_token) {
    console.log("bon token")
    console.log(request.session.infos)
    isconnected = true;
    response.redirect("/home");
    mail_token = 0;//On supprime le token afin que la page ne sois plus accessible à partir de ce lien
  } else {
    response
      .status(404)
      .send("Oups, On dirait que cette page n`est pas disponible!");
  }
});

//Traitement de deconnexion
app.post("/logout", function (request, response) {
  //On supprime la session et on redirige vers la page de login
  sess = request.session;
  var data = {
    Data: "",
  };
  sess.destroy(function (err) {
    if (err) {
      data["Data"] = "Error destroying session";
      response.json(data);
    } else {
      data["Data"] = "Session destroy successfully";
      isconnected = false;
      response.redirect("/");
    }
  });
});

//Défini sur quel port on écoute
app.listen(process.env.PORT || 3000, () => {
  console.log("Started on PORT 3000");
});