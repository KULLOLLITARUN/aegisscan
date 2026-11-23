using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

namespace App
{
    // INTENTIONALLY VULNERABLE benchmark fixture. Do not deploy.
    public class MoreSinks : Controller
    {
        public void TrustEverything()
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
        }

        public HttpClient LaxClient()
        {
            var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (m, c, ch, e) => true };
            return new HttpClient(handler);
        }

        public byte[] Fingerprint(string pw)
        {
            return SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(pw));
        }

        public IActionResult Go()
        {
            return Redirect(Request.Query["next"]);
        }

        public string ReadDoc()
        {
            return File.ReadAllText("/srv/files/" + Request.Query["name"]);
        }

        public HtmlString Bio(string bio)
        {
            return new HtmlString("<b>" + bio + "</b>");
        }

        public XmlReader ParseXml(string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            return XmlReader.Create(new StringReader(xml), settings);
        }
    }
}
