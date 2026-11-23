using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Xml;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

namespace App
{
    // Safe look-alikes for MoreSinks.cs: nothing here may be flagged.
    [Authorize]
    public class SafeMoreSinks : Controller
    {
        public void ValidateCertificates()
        {
            ServicePointManager.ServerCertificateValidationCallback =
                (sender, cert, chain, errors) => errors == SslPolicyErrors.None;
        }

        public HttpClient StrictClient()
        {
            return new HttpClient(new HttpClientHandler());
        }

        public byte[] Fingerprint(string pw)
        {
            return SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pw));
        }

        public IActionResult Go(string next)
        {
            return Url.IsLocalUrl(next) ? LocalRedirect(next) : Redirect("/");
        }

        public string ReadDoc(string name)
        {
            return File.ReadAllText(Path.Combine("/srv/files", Path.GetFileName(name)));
        }

        public HtmlString Bio(string bio)
        {
            return new HtmlString("<b>" + HtmlEncoder.Default.Encode(bio) + "</b>");
        }

        public HtmlString Banner()
        {
            return new HtmlString("<b>static</b>");
        }

        public XmlReader ParseXml(string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            return XmlReader.Create(new StringReader(xml), settings);
        }
    }
}
