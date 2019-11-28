package pkgLoginAppEx3;

import com.intel.util.*;

public class LoginController {
	private String _password;
	private boolean access;
	final int FILE_NAME = 0;

	public LoginController() {
		access = false;
		_password = null;
		int size = FlashStorage.getFlashDataSize(0);
		if (size > 0) {
			byte[] buffer = new byte[size];
			FlashStorage.readFlashData(FILE_NAME, buffer, 0);
			_password = new String(buffer);
		}
	}

	/**
	 * save password to NVM storage
	 * 
	 * @commandId 1
	 * @param password
	 * @return if success to create the password
	 */
	boolean SetPassword(String password) {
		if (_password != null) {
			return false;
		}
		_password = password;
		DebugPrint.printString("length: " + _password.length());
		DebugPrint.printBuffer(_password.getBytes());
		DebugPrint.printString("file: " + FILE_NAME);
		FlashStorage.writeFlashData(FILE_NAME, _password.getBytes(), 0, _password.length());
		return true;
	}

	/**
	 * @commandId onInit
	 * @param password
	 * @return
	 */
	boolean GetAccess(String password) {
		access = password.equals(_password);
		return access;
	}

	/**
	 * @commandId 2
	 * @param password
	 * @return
	 */
	boolean ResetPassword(String password) {
		if (!access) {
			return false;
		}
		_password = password;
		FlashStorage.writeFlashData(FILE_NAME, _password.getBytes(), 0, _password.length());
		return true;
	}

}
