using Intel.Dal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace LoginAppEx3Host
{
    enum CommandsIds
    {
        SetPassword = 1,
        ResetPassword = 2,

    }
    class CommmandsController
    {
        // This is the UUID of this Trusted Application (TA).
        //The UUID is the same value as the applet.id field in the Intel(R) DAL Trusted Application manifest.
        static readonly string appletID = "d7ce28c6-592b-4f92-be18-8a970862ce5e";

        static Jhi jhi = Jhi.Instance;
        static JhiSession session;
        static JhiSession loginSession;
        static string publicKey;

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
            jhi.SendAndRecv2(session, (int)CommandsIds.SetPassword, password, ref recvBuffer, out responseCode);
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
            if (loginSession == null) { return false; }
            byte[] recvBuffer = new byte[1];
            int responseCode;
            jhi.SendAndRecv2(loginSession, (int)CommandsIds.ResetPassword, password, ref recvBuffer, out responseCode);
            return recvBuffer[0] == 1;
        }
    }
}
