package pkgLoginAppEx3;

public class LoginController {
	private String _password;
	private boolean access = false;

	boolean SetPassword(String password) {
		if (_password != null) {
			return false;
		}
		_password = password;
		return true;
	}

	boolean GetAccess(String password) {
		access = password == _password;
		return access;
	}

	boolean ResetPassword(String password) {
		if (!access) {
			return false;
		}
		_password = password;
		return true;
	}

}
