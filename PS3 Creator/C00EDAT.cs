using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Reflection;

namespace edatat
{
    class C00EDAT
    {
        int counter1 = 0;
        public string ip;
        public string game;
        public string rifs;
        public string trash;
        public string trash2;
        public string line;
        public string line3;
        public string login;
        public string C00games;
        public string password;
        public string outFile;
        public static byte[] pad = {
        (byte) 0x47, (byte) 0x4F, (byte) 0x4D, (byte) 0x41,
        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        public string GetSubstringByString(string a, string b, string c)
        {
            return c.Substring((c.IndexOf(a)), (c.IndexOf(b) - c.IndexOf(a)));
        }
        public string makeedat(String inFile, String outFile)
        {
            if (!File.Exists(inFile))
            {
                Console.WriteLine(inFile + " not found");
                return inFile;
            }
            else
            {
                String strAppDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().GetName().CodeBase);
                string path = strAppDir.Replace("file:\\", "");
                StreamReader sfoFile = new StreamReader(inFile);
                string pkgname1 = GetSubstringByString("temp/", "/PARAM.SFO", inFile);
                string pkgname = pkgname1.Replace("temp/", "");
                // FileStream sfoFile = File.Open(inFile, FileMode.Open);
                string ciddat = sfoFile.ReadToEnd();
                if (ciddat.Contains("HG\0\0"))
                {
                    if (ciddat.Contains("Library"))
                    {
                        byte[] result = new byte[ciddat.Length];
                        string cid4 = GetSubstringByString("HG\0\0", "Library", ciddat);
                        string cid5 = cid4.Replace("HG\0\0", "");

                        int found = 0;
                        found = cid5.IndexOf("\0");

                        int cid1 = cid5.Length - found;
                        int cid2 = cid5.Length - cid1;
                        sfoFile.Close();
                        string cid = cid5.Replace("\0", "");
                        //byte[] contentID = ciddat;
                        if (cid2 > 35)
                        {

                            byte[] CID = Encoding.UTF8.GetBytes(cid);
                            byte[] contentID = new byte[48];
                            byte[] contentID2 = new byte[cid2];
                            ConversionUtils.arraycopy(CID, 0, contentID, 0, CID.Length);
                            ConversionUtils.arraycopy(CID, 0, contentID2, 0, cid2);
                            string cid3 = Encoding.UTF8.GetString(contentID2);
                            if (path != null)
                            {
                                outFile = path + "/edats/" + cid3 + ".edat";
                            }
                            else
                            {
                                outFile = "edats/" + cid3 + ".edat";
                            }
                            
                            FileStream dat = File.Open(cid3 + ".dat", FileMode.Create);
                            // byte[] pad = new byte[0x10];
                            //  Random rand = new Random();
                            //  rand.NextBytes(pad);           
                            dat.Write(pad, 0, 0x10);
                            dat.Write(contentID, 0, contentID.Length);
                            dat.Close();
                            String input = cid3 + ".dat";
                            DirectoryInfo di = Directory.CreateDirectory(path + "/edats");
                            byte[] flags = ConversionUtils.getByteArray("0C");
                            byte[] type = ConversionUtils.getByteArray("00");
                            byte[] version = ConversionUtils.getByteArray("02");
                            byte[] devKLic = ConversionUtils.getByteArray("72F990788F9CFF745725F08E4C128387");
                            byte[] keyFromRif = null;

                            EDAT instance = new EDAT();
                            instance.encryptFile(input, outFile, devKLic, keyFromRif, contentID, flags, type, version);

                            if (File.Exists(cid3 + ".dat"))
                            {
                                File.Delete(cid3 + ".dat");
                            }
                            if (input.EndsWith(".Dec"))
                            {
                                File.Delete(input);
                            }
                            System.IO.StreamWriter file =
                            new System.IO.StreamWriter("C00 list.txt", true);

                                file.WriteLine(pkgname, true);

                                file.Close();
                            return cid3 + ".edat";
                        }
                        else
                        {
                            Console.WriteLine("Content_ID not found.");
                            sfoFile.Close();
                            return "";
                        }
                    }
                    else
                    {
                        Console.WriteLine("Content_ID not found.");
                        sfoFile.Close();
                        return "";
                    }
                }
                else
                {
                    Console.WriteLine("Content_ID not found.");
                    sfoFile.Close();
                    return "";
                }
            }
        }
    }
}
            


