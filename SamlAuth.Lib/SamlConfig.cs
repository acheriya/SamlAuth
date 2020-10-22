using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SamlAuth.Lib
{
    public class SamlConfig
    {

        public SamlConfig()
        {
            ValidIssuers = new List<string>();
        }

        /// <summary>
        /// Issuers that will be used to check against the token's issuer.
        /// </summary>
        public IEnumerable<string> ValidIssuers { get; set; }

        /// <summary>
        /// Name of the Trusted Issuer, OKTA, ADFS, ACS etc
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///Trusted Issuer Certification Thumbprint
        /// </summary>
        public string CertificateThumbprint { get; set; }

        /// <summary>
        /// Audience URL
        /// </summary>
        public string Audience { get; set; }
    }
}
