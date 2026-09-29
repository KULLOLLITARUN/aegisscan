using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace App
{
    public class AccountService
    {
        private const string ConnectionString = "Server=db;Database=app;User Id=sa;Password=Adm1n-Pr0d-2024;";

        public SqlDataReader FindUser(string name)
        {
            var conn = new SqlConnection(ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
            return cmd.ExecuteReader();
        }

        public byte[] HashPassword(string pw)
        {
            return MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(pw));
        }

        public object LoadSession(Stream s)
        {
            return new BinaryFormatter().Deserialize(s);
        }

        public void Ping(string host)
        {
            Process.Start("cmd.exe", "/c ping " + host);
        }

        public XmlDocument Parse(string xml)
        {
            var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            doc.LoadXml(xml);
            return doc;
        }
    }
}
