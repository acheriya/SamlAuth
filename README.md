# SamlAuth
This is the source code for the libray that can be used for validating the incoming SAML, Supports  OKTA, ADFS, ACS issued token validation

Integrating with OKTA in ASP.NET MVC

        [HttpPost]
        public ActionResult Saml()
        {
            string saml = Request.Form["SamlResponse"];

            var samlConfig = new SamlConfig
            {
                Name = "OKTA",
                CertificateThumbprint = "444*******************454",
                Audience = "https://dev-****-admin.okta.com",
                ValidIssuers = new List<string> { "http://www.okta.com/e*****456" }
            };

            SamlAuthProvider authProvider = new SamlAuthProvider(samlConfig);

            if (authProvider.Validate(saml))
            {
                //Login using your authentication provider
                //authProvider.Name give the identity name associated with Saml
             
                return RedirectToAction("Index", "Home");
            }


            return Unauthorized();
        }
