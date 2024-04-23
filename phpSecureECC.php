<?php
/**
 * phpSecureECC v.1.0 - 23/04/2024
 * 
 * A Pure PHP Elliptic Curve Cryptography Library that implements ECDH and ECDSA using secp256k1 elliptic curve
 *
 * This library provides robust tools for secure key generation, message encryption/decryption,
 * and digital signature verification in PHP.   
 *
 * Copyright (C) 2024 under Apache License, Version 2.0
 *
 * @author Luca Soltoggio
 * https://www.lucasoltoggio.it
 * https://github.com/toggio/SecureTokenizer
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
 
class phpSecureECC {
	private $p; // Prime field of the elliptic curve
	private $G; // Base point (generator point) of the elliptic curve
	private $n; // Order of the curve

	/**
	 * Constructor for the class.
	 * Initializes the elliptic curve parameters including the prime field, the order, and the generator point.
	 */	
	public function __construct() {
		$this->p = gmp_init("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
		$this->n = gmp_init("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
		$this->G = [
			gmp_init("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
			gmp_init("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
		];
	}
	
	/**
	 * Generates a private key for elliptic curve cryptography.
	 * @return string Hexadecimal representation of the generated private key.
	 */
	public function generatePrivateKey() {
		$bytes = random_bytes(32); // 256 bit
		$hex = bin2hex($bytes);
		return $hex;
	}

	/**
	 * Derives a public key from a given private key.
	 * @param string $privateKeyHex The private key in hexadecimal format.
	 * @return string The derived public key in hexadecimal format.
	 */
	public function derivePublicKey($privateKeyHex) {
		$privateKey = gmp_init($privateKeyHex, 16);
		$publicKey = $this->secp256k1_ptmul($this->G, $privateKey, $this->p);
		$x = gmp_strval($publicKey[0], 16);
		$y = gmp_strval($publicKey[1], 16);

		$x = str_pad($x, strlen($privateKeyHex), '0', STR_PAD_LEFT);
		$y = str_pad($y, strlen($privateKeyHex), '0', STR_PAD_LEFT);

		return $x . $y;
	}

	/**
	 * Compresses a public key using the EC point compression technique.
	 * @param string $publicKeyHex The public key in hexadecimal format.
	 * @return string The compressed public key with its prefix.
	 */
	public function compressPublicKey($publicKeyHex) {
		$halfLength = strlen($publicKeyHex) / 2;
		$x = gmp_init(substr($publicKeyHex, 0, $halfLength), 16);
		$y = gmp_init(substr($publicKeyHex, $halfLength), 16);
		$prefix = gmp_mod($y, 2) == 0 ? '02' : '03';
		return $prefix . str_pad(gmp_strval($x, 16), strlen($publicKeyHex)/2, '0', STR_PAD_LEFT);
	}

	/**
	 * Decompresses a public key from its compressed format.
	 * @param string $compressedKey The compressed public key.
	 * @return string The decompressed public key in hexadecimal format.
	 */
	public function decompressPublicKey($compressedKey) {
		$prefix = substr($compressedKey, 0, 2);
		$xHex = substr($compressedKey, 2);
		$x = gmp_init($xHex, 16);
		$y = gmp_strval($this->calculateY($x, $prefix),16);
		$x = gmp_strval($x,16);
		
		$x = str_pad($x, strlen($compressedKey)-2, '0', STR_PAD_LEFT);
		$y = str_pad($y, strlen($compressedKey)-2, '0', STR_PAD_LEFT);
		
		return $x.$y;
	}

	/**
	 * Implements the Tonelli-Shanks algorithm for finding a square root of 'n' modulo 'p'
	 * when a solution exists. This algorithm is used in the context of elliptic curves over finite fields.
	 * @param GMP $n The number for which the square root is to be found modulo 'p'.
	 * @param GMP $p The modulus, a prime number, under which the calculation is performed.
	 * @return GMP|0 The square root of 'n' modulo 'p' if it exists, otherwise returns 0.
	 */
	private function tonelliShanks($n, $p) {
		if (gmp_legendre($n, $p) != 1) {
			return 0; // no solution
		}
		if (gmp_cmp($p, '2') == 0) return $p;
		if (gmp_mod($p, 4) == 3) {
			return gmp_powm($n, gmp_div_q(gmp_add($p, 1), 4), $p);
		}
		$s = 0;
		$q = gmp_sub($p, 1);
		while (gmp_mod($q, 2) == 0) {
			$s++;
			$q = gmp_div_q($q, 2);
		}
		$z = 2;
		while (gmp_legendre($z, $p) != -1) {
			$z++;
		}
		$m = $s;
		$c = gmp_powm($z, $q, $p);
		$t = gmp_powm($n, $q, $p);
		$r = gmp_powm($n, gmp_div_q(gmp_add($q, 1), 2), $p);
		while (gmp_cmp(gmp_mod($t, $p), 1) != 0) {
			$i = 0;
			$temp = $t;
			while (gmp_cmp(gmp_mod($temp, $p), 1) != 0) {
				$temp = gmp_powm($temp, 2, $p);
				$i++;
			}
			$b = gmp_powm($c, gmp_pow('2', gmp_sub($m, $i - 1)), $p);
			$m = $i;
			$c = gmp_powm($b, 2, $p);
			$t = gmp_mod(gmp_mul($t, $c), $p);
			$r = gmp_mod(gmp_mul($r, $b), $p);
		}
		return $r;
	}

	/**
	 * Calculates the Y coordinate of a point on an elliptic curve given the X coordinate and a prefix.
	 * The prefix ('02' or '03') indicates whether the Y coordinate is even or odd, respectively.
	 * @param GMP $x The X coordinate of the point.
	 * @param string $prefix The prefix indicating the parity of the Y coordinate.
	 * @return GMP The Y coordinate corresponding to the given X coordinate and prefix, on the elliptic curve defined by y^2 = x^3 + 7 mod p.
	 */
	private function calculateY($x, $prefix) {
		$y2 = gmp_mod(gmp_add(gmp_pow($x, 3), 7), $this->p);
		$y = $this->tonelliShanks($y2, $this->p);
	
		if (($prefix === '03' && gmp_mod($y, 2) == 0) || ($prefix === '02' && gmp_mod($y, 2) == 1)) {
			$y = gmp_sub($this->p, $y); 
		}
		return $y;
	}

	/**
	 * Calculates the shared secret key between two parties, using the local private key and the remote public key.
	 * @param string $privateKeyHex Local private key in hexadecimal format.
	 * @param string $publicKeyHex Remote public key in hexadecimal format.
	 * @return string The shared secret key in hexadecimal format.
	 */
	public function calculateSharedKey($privateKeyHex, $publicKeyHex) {
		$privateKey = gmp_init($privateKeyHex, 16);

		$halfLength = strlen($publicKeyHex) / 2;
		$x = gmp_init(substr($publicKeyHex, 0, $halfLength), 16);
		$y = gmp_init(substr($publicKeyHex, $halfLength), 16);
		$publicKey = [$x, $y];
		$sharedKey = $this->secp256k1_ptmul($publicKey, $privateKey, $this->p);
		
		$s1 = gmp_strval($sharedKey[0], 16);
		$s2 = gmp_strval($sharedKey[1], 16);
		
		$s1 = str_pad($s1, strlen($privateKeyHex), '0', STR_PAD_LEFT);
		$s2 = str_pad($s2, strlen($privateKeyHex), '0', STR_PAD_LEFT);
		
		return $s1 . $s2;
	}
	
	/**
	 * Signs a message using the private key.
	 * @param string $message The message to sign.
	 * @param string $privateKeyHex The private key used to sign the message in hexadecimal format.
	 * @return array Associative array containing 'r' and 's' values of the signature.
	 */
	private function signMessage($message, $privateKeyHex) {
		$e = gmp_init(hash('sha256', $message), 16);
		do {
			$k = gmp_random_range(gmp_init(1), gmp_sub($this->n, 1));
			$kG = $this->secp256k1_ptmul($this->G, $k, $this->p);
			$r = gmp_mod($kG[0], $this->n);
			if (gmp_cmp($r, 0) == 0) continue;
			$k_inv = gmp_invert($k, $this->n);
			$privateKey = gmp_init($privateKeyHex, 16);
			$s = gmp_mod(gmp_mul(gmp_invert($k, $this->n), gmp_add($e, gmp_mul($privateKey, $r))), $this->n);
		} while (gmp_cmp($s, 0) == 0);
		return ['r' => gmp_strval($r, 16), 's' => gmp_strval($s, 16)];
	}
	
	/**
	 * Verifies a signature against a given message hash and public key.
	 * @param string $messageHash Hash of the message that was signed.
	 * @param array $signature Array containing 'r' and 's' components of the signature.
	 * @param string $publicKeyHex The public key in hexadecimal format.
	 * @return bool True if the signature is valid, False otherwise.
	 */
	private function verifySignature($messageHash, $signature, $publicKeyHex) {
		$e = gmp_init($messageHash, 16);
		$r = "0x".$signature['r'];
		$s = "0x".$signature['s'];
		$xHex = substr($publicKeyHex, 0, strlen($publicKeyHex) / 2);
		$yHex = substr($publicKeyHex, strlen($publicKeyHex) / 2);
		$publicKey = [gmp_init($xHex, 16), gmp_init($yHex, 16)];
		if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, gmp_sub($this->n, 1)) > 0) return false;
		if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, gmp_sub($this->n, 1)) > 0) return false;
		$inv_s = gmp_invert($s, $this->n);
		$u1 = gmp_mod(gmp_mul($e, $inv_s), $this->n);
		$u2 = gmp_mod(gmp_mul($r, $inv_s), $this->n);
		$u1G = $this->secp256k1_ptmul($this->G, $u1, $this->p);
		$u2Q = $this->secp256k1_ptmul($publicKey, $u2, $this->p);
		$X = $this->secp256k1_addpt($u1G, $u2Q, $this->p);
		return gmp_cmp($X[0], $r) == 0;
	}

	/**
	 * Encrypts a message using ECDH derived keys.
	 * @param string $message The message to encrypt.
	 * @param string|null $privateKeyA The private key of the sender (optional).
	 * @param string|null $publicKeyB The public key of the receiver (optional).
	 * @param bool $sign If true, also sign the message.
	 * @return string The encrypted message in JSON format.
	 */
	public function encrypt ($message, $privateKeyA = null, $publicKeyB = null, $sign = false, $crypt = true) {
		if (is_null($privateKeyA)) {
			$privateKeyA = $this->generatePrivateKey();
			$publicKeyA = $this->derivePublicKey($privateKeyA);
		}
			
		$sharedKey = hash('sha3-256',hex2bin($this->calculateSharedKey($privateKeyA, $publicKeyB)));
		$secretKey = hex2bin($sharedKey);
		$iv = hex2bin(substr(hash('sha256', $secretKey), 0, 32));
		
		$message .= hex2bin(str_pad(dechex($this->crc8($message)),1,"0",STR_PAD_LEFT));

		$encMessage = openssl_encrypt($message, "AES-256-CBC", $secretKey ,OPENSSL_RAW_DATA, $iv);
		
		$encMessage .= hex2bin(str_pad(dechex($this->crc8($encMessage)),1,"0",STR_PAD_LEFT));
		
		$result["message"] = $this->encodeBase58($encMessage,true);
		
		if (isset($publicKeyA)) $result["pubkey"] = $this->encodeBase58($this->compressPublicKey($publicKeyA));
		
		if ($sign) {
			$sigArray = $this->signMessage($message,$privateKeyA);
			$result["signature"] = $this->encodeBase58($sigArray["r"].$sigArray["s"]);
		}
		
		return json_encode($result);
	}

	/**
	 * Decrypts a message using ECDH derived keys.
	 * @param string $encoded The encoded message in JSON format.
	 * @param string|null $privateKeyB The private key of the receiver.
	 * @param string|null $publicKeyA The public key of the sender.
	 * @param bool $sign If true, verify the signature.
	 * @return string|false The decrypted message if successful, or an error message.
	 */
	public function decrypt ($encoded, $privateKeyB = null, $publicKeyA = null, $sign =false, $crypt = true) {
		$result = json_decode($encoded);
	
		if (is_null($publicKeyA)) {
			$publicKeyA = $this->decompressPublicKey($this->decodeBase58($result->pubkey));
		}
		
		$sharedKey = hash('sha3-256',hex2bin($this->calculateSharedKey($privateKeyB, $publicKeyA)));
		$secretKey = hex2bin($sharedKey);
		$iv = hex2bin(substr(hash('sha256', $secretKey), 0, 32));
		
		$encMessage = $this->decodeBase58($result->message,true);
		
		$crc = hexdec(bin2hex(substr($encMessage, -1)));
		$encMessage = substr($encMessage, 0, -1);
		$cCrc = $this->crc8($encMessage);
		$check = ($cCrc === $crc);
		
		$decMessage = openssl_decrypt($encMessage, "AES-256-CBC", $secretKey, OPENSSL_RAW_DATA, $iv);
		
		if ($sign) {
			$signature = $this->decodeBase58($result->signature);
			$halfLength = strlen($signature) / 2;
			$r = substr($signature, 0, $halfLength);
			$s = substr($signature, $halfLength);
			$signArray["r"]=$r;
			$signArray["s"]=$s;
			$messageHash = hash('sha256', $decMessage);
			$signed = $this->verifySignature($messageHash, $signArray, $publicKeyA);
		} else $signed = true;
		
		$crc = hexdec(bin2hex(substr($decMessage, -1)));
		$decMessage = substr($decMessage, 0, -1);
		$cCrc = $this->crc8($decMessage);
		$check = ($cCrc === $crc) && $check;
		
		if (!$check) $error = "Error: CRC verify failed";
		if (!$signed) $error = "Error: signature non verified";
		
		$check = $check && $signed;
		
		return $check ? $decMessage : $error;
	}
	
	/**
	 * Simplified encryption method using a single known public key.
	 * @param string $message The message to encrypt.
	 * @param string $publicKey The public key of the receiver.
	 * @param bool $sign If true, sign the message.
	 * @return string The encrypted message.
	 */
	public function encryptWithSingleKey ($message, $publicKey, $sign = false) {
		return $this->encrypt($message, null, $publicKey, $sign);
	}

	/**
	 * Simplified decryption method using a single known private key.
	 * @param string $message The encrypted message.
	 * @param string $privateKey The private key of the receiver.
	 * @param bool $sign If true, verify the signature.
	 * @return string|false The decrypted message if successful, or an error message.
	 */
	public function decryptWithSingleKey ($message, $privateKey, $sign = false) {
		return $this->decrypt($message, $privateKey, null, $sign);
	}
	
	/**
	 * Signs a given message using a private key and encodes the signature in Base58.
	 * @param string $message The message to sign.
	 * @param string $privateKeyHex The private key in hexadecimal format.
	 * @return string The signature encoded in Base58.
	 */
	public function sign($message, $privateKeyHex) {
		$sigArray = $this->signMessage($message,$privateKeyHex);
		return $this->encodeBase58($sigArray["r"].$sigArray["s"]);
	}
	
	/**
	 * Verifies a given signature against a message hash and a public key.
	 * @param string $message The message that was signed.
	 * @param string $signature The signature in Base58 encoded format.
	 * @param string $publicKeyHex The public key in hexadecimal format.
	 * @return bool True if the signature is valid, false otherwise.
	 */
	public function verify($message, $signature, $publicKeyHex) {
		$signature = $this->decodeBase58($signature);
		$halfLength = strlen($signature) / 2;
		$r = substr($signature, 0, $halfLength);
		$s = substr($signature, $halfLength);
		$signArray["r"]=$r;
		$signArray["s"]=$s;
		return $this->verifySignature(hash('sha256',$message), $signArray, $publicKeyHex);
	}

	/**
	 * Calculates the multiplicative inverse of a number modulo p using the extended Euclidean algorithm.
	 * @param GMP $x The number to invert.
	 * @param GMP $p The modulo.
	 * @return GMP The inverse of x modulo p.
	 */
	private function secp256k1_inverse($x, $p) {
		$inv1 = gmp_init(1);
		$inv2 = gmp_init(0);

		while (gmp_cmp($p, 0) != 0 && gmp_cmp($p, 1) != 0) {
			list($inv1, $inv2) = array(
				$inv2,
				gmp_sub($inv1, gmp_mul($inv2, gmp_div_q($x, $p)))
			);
			list($x, $p) = array(
				$p,
				gmp_mod($x, $p)
			);
		}
		return $inv2;
	}

	/**
	 * Doubles a point on the elliptic curve using the secp256k1 parameters.
	 * @param array $point The point to double.
	 * @param GMP $p The prime defining the field of the curve.
	 * @return array|null The doubled point or null if the operation is not possible.
	 */
	private function secp256k1_dblpt($point, $p) {
		if (is_null($point)) return null;
		list($x, $y) = $point;
		if (gmp_cmp($y, "0") == 0) return null;

		$slope = gmp_mul(gmp_mul("3", gmp_pow($x, 2)), $this->secp256k1_inverse(gmp_mul("2", $y), $p));
		$slope = gmp_mod($slope, $p);

		$xsum = gmp_sub(gmp_mod(gmp_pow($slope, 2), $p), gmp_mul("2", $x));
		$ysum = gmp_sub(gmp_mul($slope, gmp_sub($x, $xsum)), $y);

		return array(gmp_mod($xsum, $p), gmp_mod($ysum, $p));
	}

	/**
	 * Adds two points on the elliptic curve using the secp256k1 parameters.
	 * @param array $p1 The first point.
	 * @param array $p2 The second point.
	 * @param GMP $p The prime defining the field of the curve.
	 * @return array|null The resulting point after addition or null if the addition is not defined.
	 */
	private function secp256k1_addpt($p1, $p2, $p) {
		if ($p1 === null || $p2 === null) return null;

		list($x1, $y1) = $p1;
		list($x2, $y2) = $p2;

		if (gmp_cmp($x1, $x2) == 0) {
			if (gmp_cmp($y1, $y2) == 0) return $this->secp256k1_dblpt($p1, $p);
			else return null;
		}

		$slope = gmp_mul(gmp_sub($y1, $y2), $this->secp256k1_inverse(gmp_sub($x1, $x2), $p));
		$slope = gmp_mod($slope, $p);

		$xsum = gmp_sub(gmp_mod(gmp_pow($slope, 2), $p), gmp_add($x1, $x2));
		$ysum = gmp_sub(gmp_mul($slope, gmp_sub($x1, $xsum)), $y1);

		return array(gmp_mod($xsum, $p), gmp_mod($ysum, $p));
	}
	
	/**
	 * Multiplies a point on the elliptic curve by a scalar using the secp256k1 parameters.
	 * @param array $pt The point to multiply.
	 * @param GMP $a The scalar multiplier.
	 * @param GMP $p The prime defining the field of the curve.
	 * @return array|null The resulting point after multiplication.
	 */
	private function secp256k1_ptmul($pt, $a, $p) {
		$scale = $pt;
		$acc = null;

		while (gmp_cmp($a, "0") != 0) {
			if (gmp_mod($a, 2) == 1) {
				$acc = $acc === null ? $scale : $this->secp256k1_addpt($acc, $scale, $p);
			}
			$scale = $this->secp256k1_dblpt($scale, $p);
			$a = gmp_div_q($a, 2);
		}
		return $acc;
	}
	
	/**
	 * Encodes data into Base58.
	 * @param mixed $data The data to encode. If raw is true, data must be binary.
	 * @param bool $raw Indicates if the data is raw binary data that needs to be converted to hex first.
	 * @return string The data encoded in Base58.
	 */
	public function encodeBase58($data, $raw = false) {
		if ($raw) $data = bin2hex($data);
		$zeroCount = 0;
		while (substr($data, 2*$zeroCount, 2) === '00') {
			$zeroCount++;
		}
		$base58Chars = array_merge(range('1', '9'), range('A', 'H'), range('J', 'N'), range('P', 'Z'), range('a', 'k'), range('m', 'z'));
		$n = gmp_init(strtoupper($data), 16);
		$base58 = '';
		while (gmp_cmp($n, 0) > 0) {
			list($n, $rem) = gmp_div_qr($n, 58);
			$base58 = $base58Chars[gmp_intval($rem)] . $base58;
		}
		return str_repeat('1', $zeroCount) . $base58;
	}
	
	/**
	 * Decodes data from Base58.
	 * @param string $base58 The Base58 encoded string.
	 * @param bool $raw Indicates if the result should be returned as raw binary data.
	 * @return mixed The decoded data, either as a binary string if raw is true or as a hexadecimal string.
	 */
	public function decodeBase58($base58, $raw = false) {
		$zeroCount = 0;
		while ($base58[$zeroCount] === '1') {
			$zeroCount++;
		}
		$base58 = substr($base58, $zeroCount);
		$base58Chars = array_merge(range('1', '9'), range('A', 'H'), range('J', 'N'), range('P', 'Z'), range('a', 'k'), range('m', 'z'));
		$values = array_flip($base58Chars);
		$n = gmp_init(0);

		for ($i = 0; $i < strlen($base58); $i++) {
			$value = $values[$base58[$i]];
			$n = gmp_add(gmp_mul($n, 58), $value);
		}

		$hex = gmp_strval($n, 16);
		if (strlen($hex) % 2 != 0) {
			$hex = '0' . $hex; 
		}
	
		$hex = str_repeat('00', $zeroCount) . $hex;

		return $raw ? hex2bin($hex) : $hex;
	}
	
	/**
	 * Calculates the CRC8 checksum for the given data.
	 * @param string $data The data to calculate the CRC for.
	 * @return int The CRC8 checksum.
	 */
	public function crc8($data) {
		$crc = 0x00;
		foreach (str_split($data) as $char) {
			$crc ^= ord($char);
			for ($i = 0; $i < 8; $i++) {
				if (($crc & 0x80) != 0) {
					$crc = (($crc << 1) ^ 0x07) & 0xFF;
				} else {
					$crc <<= 1;
				}
			}
		}
		return $crc;
	}	

}
?>
