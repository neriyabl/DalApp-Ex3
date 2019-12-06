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
            CommmandsController.connect();
            
            Console.WriteLine("enter password");
            string password = Console.ReadLine();

            var isNewPassword = CommmandsController.SetPassword(Encoding.UTF8.GetBytes(password));

            if (isNewPassword)
            {
                Console.WriteLine("\tsuccess to create new password");
                CommmandsController.GetAccess(Encoding.UTF8.GetBytes(password));
            }
            else
            {
                Console.WriteLine("\talrady have password");
                Console.WriteLine("\ttry to get access");
                Console.WriteLine("\tenter the password");
                password = Console.ReadLine();
                CommmandsController.GetAccess(Encoding.UTF8.GetBytes(password));
            }
            Console.WriteLine();

            Console.WriteLine("want to change the password? [yes/no]");
            var changePass = Console.ReadLine();

            if (changePass == "yes")
            {
                Console.WriteLine("enter the new password");
                var newPassword = Console.ReadLine();
                if (CommmandsController.ResetPassword(Encoding.UTF8.GetBytes(newPassword)))
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

}