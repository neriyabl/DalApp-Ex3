using System;
using System.Text;
using Intel.Dal;

namespace LoginAppEx3Host
{
    class Program
    {
        static void Main(string[] args)
        {
#if AMULET
            // When compiled for Amulet the Jhi.DisableDllValidation flag is set to true 
            // in order to load the JHI.dll without DLL verification.
            // This is done because the JHI.dll is not in the regular JHI installation folder, 
            // and therefore will not be found by the JhiSharp.dll.
            // After disabling the .dll validation, the JHI.dll will be loaded using the Windows search path
            // and not by the JhiSharp.dll (see http://msdn.microsoft.com/en-us/library/7d83bc18(v=vs.100).aspx for 
            // details on the search path that is used by Windows to locate a DLL) 
            // In this case the JHI.dll will be loaded from the $(OutDir) folder (bin\Amulet by default),
            // which is the directory where the executable module for the current process is located.
            // The JHI.dll was placed in the bin\Amulet folder during project build.
            Jhi.DisableDllValidation = true;
#endif
            Handler.connect();

            Console.WriteLine("enter password");
            string password = Console.ReadLine();

            var isNewPassword = Handler.SetPassword(Encoding.UTF8.GetBytes(password));

            if (isNewPassword)
            {
                Console.WriteLine("\tsuccess to create new password");
                Handler.GetAccess(Encoding.UTF8.GetBytes(password));
            }
            else
            {
                Console.WriteLine("\talrady have password");
                Console.WriteLine("\ttry to get access");
                Console.WriteLine("\tenter the password");
                password = Console.ReadLine();
                Handler.GetAccess(Encoding.UTF8.GetBytes(password));
            }
            Console.WriteLine();

            Console.WriteLine("want to change the password? [yes/no]");
            var changePass = Console.ReadLine();

            if (changePass == "yes")
            {
                Console.WriteLine("enter the new password");
                var newPassword = Console.ReadLine();
                if (Handler.ResetPassword(Encoding.UTF8.GetBytes(newPassword)))
                {
                    Console.WriteLine("\tthe password changed");
                }
                else
                {
                    Console.WriteLine("\tyou dont have access");
                }
            }

            Console.WriteLine("Press Enter to finish.");
            Console.Read();
        }
    }

    class Handler
    {
        // This is the UUID of this Trusted Application (TA).
        //The UUID is the same value as the applet.id field in the Intel(R) DAL Trusted Application manifest.
        static readonly string appletID = "d7ce28c6-592b-4f92-be18-8a970862ce5e";

        static Jhi jhi = Jhi.Instance;
        static JhiSession session;
        static JhiSession loginSession;

        public static void connect()
        {
            // This is the path to the Intel Intel(R) DAL Trusted Application .dalp file that was created by the Intel(R) DAL Eclipse plug-in.
            string appletPath = "C:\\Users\\user\\Desktop\\dal projects\\DalApp-Ex3\\LoginAppEx3\\bin\\LoginAppEx3-debug.dalp";

            // Install the Trusted Application
            Console.WriteLine("Installing the applet.");
            jhi.Install(appletID, appletPath);

            // Start a session with the Trusted Application
            byte[] initBuffer = new byte[] { }; // Data to send to the applet onInit function
            Console.WriteLine("Opening a session.");
            jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, initBuffer, out session);
        }

        public static void disconect()
        {
            if (loginSession != null)
            {
                jhi.CloseSession(loginSession);
            }

            // Close the session
            Console.WriteLine("Closing the session.");
            jhi.CloseSession(session);

            //Uninstall the Trusted Application
            Console.WriteLine("Uninstalling the applet.");
            jhi.Uninstall(appletID);
        }

        public static bool SetPassword(byte[] password)
        {
            byte[] recvBuffer = new byte[1];
            int responseCode;
            jhi.SendAndRecv2(session, 1, password, ref recvBuffer, out responseCode);
            return recvBuffer[0] == 1;
        }

        public static bool GetAccess(byte[] password)
        {
            try
            {
                jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, password, out loginSession);
                return true;
            }
            catch
            {
                loginSession = null;
                return false;
            }
        }

        public static bool ResetPassword(byte[] password)
        {
            if(loginSession == null) { return false; }
            byte[] recvBuffer = new byte[1];
            int responseCode;
            jhi.SendAndRecv2(loginSession, 2, password, ref recvBuffer, out responseCode);
            return recvBuffer[0] == 1;
        }
    }
}