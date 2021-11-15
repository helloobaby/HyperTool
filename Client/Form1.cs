using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;

namespace Client
{
    public partial class Form1 : Form
    {
        IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);//(-1)

        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint GENERIC_EXECUTE = 0x20000000;
        const uint GENERIC_ALL = 0x10000000;

        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;

        const uint CREATE_NEW = 1;
        const uint CREATE_ALWAYS = 2;
        const uint OPEN_EXISTING = 3;
        const uint OPEN_ALWAYS = 4;
        const uint TRUNCATE_EXISTING = 5;

        const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        const uint METHOD_BUFFERED = 0;
        const uint FILE_READ_ACCESS = 0x0001;
        const uint FILE_WRITE_ACCESS = 0x0002;

        public Form1()
        {
            InitializeComponent();
        }

        uint CTL_CODE(uint DeviceType,uint Function,uint Method,uint Access)
        {
            return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method));
        }

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
        [MarshalAs(UnmanagedType.LPTStr)] string filename,
        [MarshalAs(UnmanagedType.U4)] uint access,
        [MarshalAs(UnmanagedType.U4)] uint share,
        uint securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
        [MarshalAs(UnmanagedType.U4)] uint creationDisposition,
        [MarshalAs(UnmanagedType.U4)] uint flagsAndAttributes,
        IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        private void button1_Click(object sender, EventArgs e)
        {
            IntPtr FileHandle = CreateFile("\\\\.\\HyperTool", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                0, OPEN_EXISTING, 0, IntPtr.Zero);

            if (FileHandle == INVALID_HANDLE_VALUE)
            {
                return;
            }

            uint byteRet = 0;
            DeviceIoControl(FileHandle, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_READ_ACCESS),
                IntPtr.Zero, 0, IntPtr.Zero, 0, out byteRet, IntPtr.Zero);

            CloseHandle(FileHandle);

        }

        private void button2_Click(object sender, EventArgs e)
        {

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void label3_Click(object sender, EventArgs e)
        {

        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
