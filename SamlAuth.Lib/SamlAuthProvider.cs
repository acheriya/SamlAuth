using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

/// <summary>
/// SamlAuth.Lib validate the saml 
/// </summary>
namespace SamlAuth.Lib
{
    public class SamlAuthProvider
    {

        private const string AssertionURN = "urn:oasis:names:tc:SAML:2.0:assertion";
        private SamlConfig _config;

        /// <summary>
        /// Provides the idenity user name
        /// </summary>
        public string Name
        {
            get;
            private set;
        }

        public SamlAuthProvider(SamlConfig trustedIssuer)
        {
            _config = trustedIssuer;
        }

        /// <summary>
        /// Validates the SAML Token
        /// </summary>
        /// <param name="saml"></param>
        /// <returns>true if SAML is valid</returns>
        public bool Validate(string saml)
        {
            bool isValid = false;

            string incomingSamlToken = Encoding.UTF8.GetString(Convert.FromBase64String(saml));

            var assertion = DeserializeAssertion(incomingSamlToken);
            var identity = ValidateSamlToken(assertion);

            if (identity != null)
            {
                this.Name = GetNameID(assertion);

                ValidateAudiance(assertion);
                ValidateIssuer(assertion);
                ValidateTimeStamp(assertion);

                isValid = true;
            }
            else
            {
                throw new Exception("Saml could not be verified");
            }

            return isValid;
        }

        /// <summary>
        ///  Gets the identifier for the subject
        /// </summary>
        /// <param name="assertion"></param>
        /// <returns></returns>
        protected string GetNameID(Saml2SecurityToken assertion)
        {
            string nameID = assertion.Assertion.Subject.NameId.Value;
            return nameID;
        }

        /// <summary>
        ///   Gets the identifier for the SAML authority that is making the claim(s)
        //     in the assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <param name="assertion"></param>
        /// <returns></returns>
        protected string GetIssuer(Saml2SecurityToken assertion)
        {
            string issuervalue = assertion.Assertion.Issuer.Value;
            return issuervalue;
        }

        /// <summary>
        /// Multiple audience can be validated. Check at least one audiance urls exist then allow passage.         
        /// </summary>
        /// <param name="assertion"></param>
        protected void ValidateAudiance(Saml2SecurityToken assertion)
        {
            if (String.IsNullOrEmpty(_config.Audience))
                throw new Exception("Missing Audience, specify the Audience URL.");

            Uri audienceUri = new Uri(_config.Audience);

            if (!assertion.Assertion.Conditions.AudienceRestrictions.Any(m => m.Audiences.Any(o => o == audienceUri)))
            {
                throw new Exception("Issuer is not matching with the provided valid audiences.");
            }

        }


        /// <summary>
        /// Issuer URL should be a perfect match including case with the IDP
        /// </summary>
        /// <param name="assertion"></param>
        protected void ValidateIssuer(Saml2SecurityToken assertion)
        {
            if (_config.ValidIssuers.Count() > 0)
            {
                string issuer = GetIssuer(assertion);

                if (!_config.ValidIssuers.Any(m => m == issuer))
                {
                    throw new Exception("Issuer is not matching with the provided valid issuers.");
                }
            }
        }

        /// <summary>
        ///  Current time should be LESS THAN TimeStamp NotOnOrAfter UTC
        ///  Current time should be MORE THAN TimeStamp NotBefore UTC
        /// </summary>
        /// <param name="assertion"></param>
        protected void ValidateTimeStamp(Saml2SecurityToken assertion)
        {
            DateTime notOnOrAfter = assertion.Assertion.Conditions.NotOnOrAfter.Value;
            DateTime notBefore = assertion.Assertion.Conditions.NotBefore.Value;

            if (DateTime.UtcNow >= notOnOrAfter)
            {
                throw new Exception("Current time should be LESS THAN TimeStamp NotOnOrAfter UTC");
            }

            if (DateTime.UtcNow <= notBefore)
            {
                throw new Exception("Current time should be MORE THAN TimeStamp NotBefore UTC");
            }
        }

        /// <summary>
        /// Deserialize the Assertion
        /// </summary>
        /// <param name="rawAssertion"></param>
        /// <returns></returns>
        protected Saml2SecurityToken DeserializeAssertion(string rawAssertion)
        {
            Saml2SecurityToken assertion;
            using (var reader = XmlReader.Create(new StringReader(rawAssertion)))
            {
                reader.ReadToFollowing("Assertion", AssertionURN);
                SecurityTokenHandlerCollection thc = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
                assertion = (Saml2SecurityToken)thc.ReadToken(reader.ReadSubtree());
            }
            return assertion;
        }

        /// <summary>
        /// Validate the assertion
        /// </summary>
        /// <param name="assertion"></param>
        /// <returns></returns>
        protected ClaimsIdentity ValidateSamlToken(SecurityToken assertion)
        {
            Saml2PropertiesRemoval(assertion);

            var configuration = new SecurityTokenHandlerConfiguration();
            configuration.RevocationMode = X509RevocationMode.NoCheck;

            // You can flip this switch if you don't want to make sure that IDP certificate 
            // is in the trusted root store of the Local Machine
            // configuration.CertificateValidator = X509CertificateValidator.None;
            configuration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            configuration.CertificateValidationMode = X509CertificateValidationMode.None;

            var registry = new ConfigurationBasedIssuerNameRegistry();

            registry.AddTrustedIssuer(_config.CertificateThumbprint, _config.Name);
            configuration.IssuerNameRegistry = registry;

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(configuration);

            try
            {
                var identity = handler.ValidateToken(assertion).First();

                return identity;
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        protected void Saml2PropertiesRemoval(SecurityToken St)
        {            
            var samlAssertion = St as Saml2SecurityToken;
            if (samlAssertion != null &&
                samlAssertion.Assertion != null &&
                samlAssertion.Assertion.Subject != null &&
                samlAssertion.Assertion.Subject.SubjectConfirmations != null &&
                samlAssertion.Assertion.Subject.SubjectConfirmations.Count > 0 &&
                samlAssertion.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData != null)
            {

                var subjectConfirmationData = samlAssertion.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData;
                subjectConfirmationData.Address = null;
                subjectConfirmationData.InResponseTo = null;
                subjectConfirmationData.Recipient = null;
            }
        }


    }
}
