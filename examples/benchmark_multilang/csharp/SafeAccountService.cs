using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;

namespace App
{
    public class SafeAccountService
    {
        private static readonly Regex HostPattern = new Regex("^[A-Za-z0-9.-]{1,253}$");
        private readonly string _connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");

        public SqlDataReader FindUser(string name)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
            cmd.Parameters.AddWithValue("@name", name);
            return cmd.ExecuteReader();
        }

        public byte[] HashPassword(string pw, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(pw, salt, 210_000, HashAlgorithmName.SHA256, 32);
        }

        public T LoadSession<T>(Stream s)
        {
            return JsonSerializer.Deserialize<T>(s);
        }

        public void Ping(string host)
        {
            if (!HostPattern.IsMatch(host))
            {
                throw new ArgumentException("bad host");
            }
            var psi = new ProcessStartInfo("ping") { UseShellExecute = false };
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add("1");
            psi.ArgumentList.Add(host);
            Process.Start(psi);
        }

        public XmlDocument Parse(string xml)
        {
            var doc = new XmlDocument { XmlResolver = null };
            doc.LoadXml(xml);
            return doc;
        }
    }
}
