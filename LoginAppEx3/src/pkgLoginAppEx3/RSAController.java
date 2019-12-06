package pkgLoginAppEx3;

import com.intel.crypto.HashAlg;
import com.intel.crypto.RsaAlg;
import com.intel.langutil.ArrayUtils;
import com.intel.util.DebugPrint;
import com.intel.util.FlashStorage;

public class RSAController {
	private final static int FLASH_FILE = 1;

	private final short modulusSize;
	private byte[] modulus;

	private RsaAlg rsa;
	private HashAlg hash;

	private short publicKeySize;
	private short privateKeySize;
	private byte[] privateKey;
	private byte[] publicKey;

	public RSAController() {
		modulusSize = 256;
		rsa = RsaAlg.create();
		rsa.setHashAlg(RsaAlg.HASH_TYPE_SHA512);
		hash = HashAlg.create(HashAlg.HASH_TYPE_SHA512);
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

		try {
			// save the keys in storage in the same protocol of send keys
			int bufferSize = 6 + modulusSize + publicKeySize + privateKeySize;
			byte[] buffer = new byte[bufferSize];
			buffer[0] = (byte) modulusSize;
			buffer[1] = (byte) (modulusSize >> 8);
			ArrayUtils.copyByteArray(modulus, 0, buffer, 2, modulusSize);
			buffer[modulusSize + 2] = (byte) publicKeySize;
			buffer[modulusSize + 3] = (byte) (publicKeySize >> 8);
			ArrayUtils.copyByteArray(publicKey, 0, buffer, modulusSize + 4, publicKeySize);
			buffer[modulusSize + publicKeySize + 4] = (byte) privateKeySize;
			buffer[modulusSize + publicKeySize + 5] = (byte) (privateKeySize >> 8);
			ArrayUtils.copyByteArray(privateKey, 0, buffer, modulusSize + publicKeySize + 6, privateKeySize);

			FlashStorage.writeFlashData(FLASH_FILE, buffer, 0, bufferSize);
		} catch (Exception e) {
			DebugPrint.printInt(FlashStorage.getMaxFileName());
			DebugPrint.printString(e.getMessage());
			// TODO: handle exception
		}

	}

	public byte[][] getPublicKey() {
		byte[][] result = new byte[2][];
		if (modulus.length != 0 && publicKey.length != 0) {
			result[0] = new byte[modulusSize];
			result[1] = new byte[publicKeySize];
			ArrayUtils.copyByteArray(modulus, 0, result[0], 0, modulusSize);
			return result;
		}
		return null;
	}

	public byte[] signData(byte[] data) {
		byte[] dataHashed = new byte[512];
		hash.processComplete(data, (short) 0, (short) data.length, dataHashed, (short) 0);
		byte[] buffer = new byte[1000];
		int signatureLength = rsa.signHash(dataHashed, (short) 0, (short) dataHashed.length, buffer, (short) 0);
		byte[] signedData = new byte[signatureLength];
		ArrayUtils.copyByteArray(buffer, 0, signedData, 0, signatureLength);
		return signedData;
	}

	private void tryToGetKeysFromStorage() {
		try {
			int bufferSize = FlashStorage.getFlashDataSize(FLASH_FILE);
			byte[] buffer = new byte[bufferSize];
			FlashStorage.readFlashData(FLASH_FILE, buffer, 0);

			short modulusBufferSize = (short) (buffer[0] + (buffer[1] << 8));
			ArrayUtils.copyByteArray(buffer, 2, modulus, 0, modulusBufferSize);

			publicKeySize = (short) (buffer[2 + modulusSize] + (buffer[3 + modulusSize] << 8));
			publicKey = new byte[publicKeySize];
			ArrayUtils.copyByteArray(buffer, modulusSize + 4, modulus, 0, publicKeySize);

			int privateKeyIdx = 4 + modulusBufferSize + privateKeySize;
			privateKeySize = (short) (buffer[privateKeyIdx] + (buffer[privateKeyIdx + 1] << 8));
			privateKey = new byte[privateKeySize];
			ArrayUtils.copyByteArray(buffer, privateKeyIdx + 2, privateKey, 0, privateKeySize);

			rsa.setKey(modulus, (short) 0, modulusSize, publicKey, (short) 0, publicKeySize, privateKey, (short) 0,
					privateKeySize);
		} catch (Exception e) {
			modulus = null;
			publicKeySize = 0;
			publicKey = null;
			privateKeySize = 0;
			privateKey = null;
		}
	}
}
