package pkgLoginAppEx3;

import com.intel.langutil.*;
import com.intel.crypto.HashAlg;
import com.intel.crypto.RsaAlg;
import com.intel.util.FlashStorage;

public class RSAController {
	private final static int MODULUS = 1;
	private final static int PUBLIC_KEY_FILE = 2;
	private final static int PRIVATE_KEY_FILE = 3;

	private final short modulusSize;
	private byte[] modulus;
	private RsaAlg rsa;

	private short publicKeySize;
	private short privateKeySize;
	private byte[] privateKey;
	private byte[] publicKey;

	public RSAController() {
		modulusSize = 256;
		rsa = RsaAlg.create();
		rsa.setHashAlg(HashAlg.HASH_TYPE_SHA512);
		tryToGetKeysFromStorage();
	}

	public void generateKeys() {
		rsa.generateKeys(modulusSize);

		publicKeySize = rsa.getPublicExponentSize();
		privateKeySize = rsa.getPrivateExponentSize();

		modulus = new byte[modulusSize];
		publicKey = new byte[publicKeySize];
		privateKey = new byte[privateKeySize];
		// get the keys
		rsa.getKey(modulus, (short) 0, publicKey, (short) 0, privateKey, (short) 0);

		// save the keys in storage
		FlashStorage.writeFlashData(MODULUS, modulus, 0, modulusSize);
		FlashStorage.writeFlashData(PUBLIC_KEY_FILE, publicKey, 0, publicKeySize);
		FlashStorage.writeFlashData(PRIVATE_KEY_FILE, privateKey, 0, privateKeySize);

	}

	public byte[][] getPublicKey() {
		byte[][] result = new byte[2][];
		if (modulus.length != 0 && publicKey.length != 0) {
			result[0] = new byte[modulusSize];
			result[1] = new byte[privateKeySize];
			return result;
		}
		return null;
	}

	private void tryToGetKeysFromStorage() {
		try {
			modulus = new byte[modulusSize];
			publicKey = new byte[2500];
			FlashStorage.readFlashData(MODULUS, modulus, 0);
			publicKeySize = (short)FlashStorage.readFlashData(PUBLIC_KEY_FILE, publicKey, 0);
			if (publicKeySize == 2500) {
				// TODO check rest key
			}
			privateKeySize = (short)FlashStorage.readFlashData(PRIVATE_KEY_FILE, privateKey, 0);
			if (privateKeySize == 2500) {
				// TODO check rest key
			}
		} catch (Exception e) {
			modulus = null;
			publicKeySize = 0;
			publicKey = null;
			privateKeySize = 0;
			privateKey = null;
		}
	}
}
