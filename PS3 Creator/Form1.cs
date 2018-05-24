using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using edatat;
using System.IO;
using System.Reflection;

namespace PS3_Creator
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        List<String> pkglist = new List<string>(); //pkg list
        List<String> pkgID = new List<string>();//to get each package file name
        private byte[] AesKey = new byte[0x10];
        private byte[] PKGFileKey = new byte[0x10];
        private byte[] PS3AesKey = new byte[] { 0x2e, 0x7b, 0x71, 0xd7, 0xc9, 0xc9, 0xa1, 0x4e, 0xa3, 0x22, 0x1f, 0x18, 0x88, 40, 0xb8, 0xf8 };
        private byte[] PSPAesKey = new byte[] { 7, 0xf2, 0xc6, 130, 0x90, 0xb5, 13, 0x2c, 0x33, 0x81, 0x8d, 0x70, 0x9b, 0x60, 230, 0x2b };
        private uint uiEncryptedFileStartOffset;

        private static void scan_files()
        {
            IEnumerable<string> enumerable;
            Exception exception;
            string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase).Replace(@"file:\", "");
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.pkg", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    Console.WriteLine(str4);
                    pkg2edat(str4);
                }
            }
            catch (Exception exception1)
            {
                exception = exception1;
                Console.WriteLine(exception.Message);
            }
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.rif", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    Console.WriteLine(str4);
                    rif2rap(str4);
                }
            }
            catch (Exception exception5)
            {
                exception = exception5;
                Console.WriteLine(exception.Message);
            }
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.sfo", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    Console.WriteLine(str4);
                    sfo2edat(str4);
                }
            }
            catch (Exception exception2)
            {
                exception = exception2;
                Console.WriteLine(exception.Message);
            }
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.rap", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    Console.WriteLine(str4);

                    rap2rif(str4);
                }
            }
            catch (Exception exception3)
            {
                exception = exception3;
                Console.WriteLine(exception.Message);
            }
        }
        private static void pkg2edat(string infile)
        {
            string str = null;
            str = new pkg2sfo().DecryptPKGFile(infile);
            if (Directory.Exists("temp"))
            {
                Directory.Delete("temp", true);
            }
            if (str.EndsWith(".edat"))
            {
                Console.WriteLine("Created " + str);
            }
        }

        private static void rap2rif(string infile)
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            string outFile = null;
            outFile = new edatat.rap2rif().makerif(infile, outFile);
            if (Directory.Exists("temp"))
            {
                Directory.Delete("temp", true);
            }
            if (outFile.EndsWith(".rif"))
            {
                Console.WriteLine("Created And Added To \n" + Application.StartupPath + @"\rifs\");
            }
        }

        private static void rif2rap(string infile)
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            string str2 = null;
            str2 = new edatat.rif2rap().makerap(infile);
            if (Directory.Exists("temp"))
            {
                Directory.Delete("temp", true);
            }
            if (str2.EndsWith(".rap"))
            {
                Console.WriteLine("Created " + str2);
            }

        }

        private static void sfo2edat(string infile)
        {
            string outFile = null;
            outFile = new C00EDAT().makeedat(infile, outFile);
            if (Directory.Exists("temp"))
            {
                Directory.Delete("temp", true);
            }
            if (outFile.EndsWith(".edat"))
            {
                Console.WriteLine("Created " + outFile);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            
            IEnumerable<string> enumerable;
            string path = Application.StartupPath;
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.pkg", SearchOption.AllDirectories);
                try
                {
                   if (enumerable.Count() >= 1)
                   {
                       MessageBox.Show("Some Leftovers Where Found Clearing Them", "Leftovers", MessageBoxButtons.OK, MessageBoxIcon.Information);
                   }
                }
                catch
                {

                }
                foreach (string str4 in enumerable)
                {
                    File.Delete(str4);
                }
            }
            catch
            {
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            OpenFileDialog theDialog = new OpenFileDialog();
            theDialog.Title = "Select PS3 PKG File";
            theDialog.Filter = "PS3 PKG Files|*.pkg";
            theDialog.InitialDirectory = System.Environment.SpecialFolder.MyComputer.ToString();
            if (theDialog.ShowDialog() == DialogResult.OK)
            {
                pkglist.Add(new DirectoryInfo(theDialog.FileName.ToString()).FullName);//add the pkg to a list so we can do batch install still working out the kinks
                listBox1.Items.Add(new DirectoryInfo(theDialog.FileName.ToString()).Name);
            }

        }

        private void button1_Click(object sender, EventArgs e)
        {
            foreach(string item in pkglist)
            {
                File.Copy(item, Application.StartupPath + @"\\" + new FileInfo(item).Name, true);
            }
            this.button1.Enabled = false;
            try
            {
                scan_files();
            }
            catch
            {

            }
            backgroundWorker1.RunWorkerAsync();
            MessageBox.Show("All Possible Edats Created \n Time To Cleanup","Done",MessageBoxButtons.OK,MessageBoxIcon.Information);
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            this.button1.Invoke(new Action(() => this.button1.Text = "Cleaning Up"));
            this.button1.Invoke(new Action(() => this.button1.Enabled = false));
            IEnumerable<string> enumerable;
            string path = Application.StartupPath;
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.pkg", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    File.Delete(str4);
                }
            }
            catch
            {
            }
            try
            {
                enumerable = Directory.EnumerateFiles(path, "*.DEC", SearchOption.AllDirectories);
                foreach (string str4 in enumerable)
                {
                    File.Delete(str4);
                }
            }
            catch
            {
            }
        }

        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            listBox1.Items.Clear();
            this.button1.Invoke(new Action(() => this.button1.Text = "Create Edat's"));
            this.button1.Invoke(new Action(() => this.button1.Enabled = true));
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (Directory.Exists(Application.StartupPath + @"\\edats"))
            System.Diagnostics.Process.Start(Application.StartupPath +@"\\edats");
            else
                System.Diagnostics.Process.Start(Application.StartupPath);
        }
    }
}
