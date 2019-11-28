package pkgLoginAppEx3;

import com.intel.util.*;

//
// Implementation of DAL Trusted Application: LoginAppEx3 
//
// **************************************************************************************************
// NOTE:  This default Trusted Application implementation is intended for DAL API Level 7 and above
// **************************************************************************************************

public class LoginApp extends IntelApplet {
	private LoginController loginController;

	/**
	 * This method will be called by the VM when a new session is opened to the
	 * Trusted Application and this Trusted Application instance is being created to
	 * handle the new session. This method cannot provide response data and
	 * therefore calling setResponse or setResponseCode methods from it will throw a
	 * NullPointerException.
	 * 
	 * @param request the input data sent to the Trusted Application during session
	 *                creation
	 * 
	 * @return APPLET_SUCCESS if the operation was processed successfully, any other
	 *         error status code otherwise (note that all error codes will be
	 *         treated similarly by the VM by sending "cancel" error code to the SW
	 *         application).
	 */
	public int onInit(byte[] request) {
		loginController = new LoginController();
		if (request.length > 0) {
			DebugPrint.printString("get access");
			boolean access = loginController.GetAccess(new String(request));
			return access ? APPLET_SUCCESS : APPLET_ERROR_GENERIC;
		}
		DebugPrint.printString("Hello, DAL!");
		return APPLET_SUCCESS;
	}

	/**
	 * This method will be called by the VM to handle a command sent to this Trusted
	 * Application instance.
	 * 
	 * @param commandId the command ID (Trusted Application specific)
	 * @param request   the input data for this command
	 * @return the return value should not be used by the applet
	 */
	public int invokeCommand(int commandId, byte[] request) {
		boolean result = false;

		DebugPrint.printString("Received command Id: " + commandId + ".");
		if (request != null) {
			DebugPrint.printString("Received passsword: ");

			String password = new String(request);
			DebugPrint.printString(password);
			
			byte[] res = new byte[200];
			int len = getSessionId(res, 0);
			DebugPrint.printString(new String(res).substring(0, len));

			switch (commandId) {
			case 1:
				DebugPrint.printString("set new password");
				result = loginController.SetPassword(password);
				break;
			case 2:
				DebugPrint.printString("reset password");
				result = loginController.ResetPassword(password);
				break;
			default:
				break;
			}

		}

		final byte[] myResponse = { (byte) (result ? 1 : 0) };

		/*
		 * To return the response data to the command, call the setResponse method
		 * before returning from this method. Note that calling this method more than
		 * once will reset the response data previously set.
		 */
		setResponse(myResponse, 0, myResponse.length);

		/*
		 * In order to provide a return value for the command, which will be delivered
		 * to the SW application communicating with the Trusted Application,
		 * setResponseCode method should be called. Note that calling this method more
		 * than once will reset the code previously set. If not set, the default
		 * response code that will be returned to SW application is 0.
		 */
		setResponseCode(commandId);

		/*
		 * The return value of the invokeCommand method is not guaranteed to be
		 * delivered to the SW application, and therefore should not be used for this
		 * purpose. Trusted Application is expected to return APPLET_SUCCESS code from
		 * this method and use the setResposeCode method instead.
		 */
		return APPLET_SUCCESS;
	}

	/**
	 * This method will be called by the VM when the session being handled by this
	 * Trusted Application instance is being closed and this Trusted Application
	 * instance is about to be removed. This method cannot provide response data and
	 * therefore calling setResponse or setResponseCode methods from it will throw a
	 * NullPointerException.
	 * 
	 * @return APPLET_SUCCESS code (the status code is not used by the VM).
	 */
	public int onClose() {
		loginController = null;
		DebugPrint.printString("Goodbye, DAL!");
		return APPLET_SUCCESS;
	}
}
