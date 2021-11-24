import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


/**
 * a: 22548155496845254710235689745815
 * A: 963A89C1D497592FADC4E7D7B00F391CC0A3DEF1B786CC3DDB853D281BFAADA694124AA8315BF4DED41CABC2401338E63F470CAAB27ECD1B5AC42EFDB1CCBF583B03CA5899AAAE6D0403503E6736E4D4CE1696AB91F58CD2B5CCB449562B0E6C404381CB2D3C548E3C44E007CFC4EB3718816D49861A1AA924F22C8D0A06EB16
 * V: 122335542910222275053509868645101784567719922110224539568368767851893375862114626370688422700040698985860377351447563945436600626884462653333100949028612337406473699194902873666842731008032539698358754220556314631352628996832882187975689438519122315582128984303536621018777271389393329585936879618663790040282
 * S: F4729CCB6D2E9597E2D14FF1E9BCB51119969F10626071F5DC90214D0294B6CB
 * K: F4729CCB6D2E9597E2D14FF1E9BCB511
 * IV: 8BEB2187C844936BAF6E96A77953C827
 * Encrypted Message: 8BEB2187C844936BAF6E96A77953C827231108AD1D3E59CE8F76368C966A3DE745FF140093E697BBCD675781006B403B2FBBBBE294D8536A8938EE9B159EB8979434CC1EB76FD4CEA070D1343EAF9144D2437F7B56E4A54B41E7850EE46F130CD5465242261AC5E141E4DB37FFD82095601B0B9689672C1B9F62EA9929E559F32CC5077DDAD0C6D239DCAA4C099FDF77930BBF595F96BFC442D0127D4D438D30
 * Decrypted Message: Excelente. Funcionou. Agora comenta bem o código, coloca este exemplo completo como comentário no início do código e submete no Moodle.
 * Reversed Message: .eldooM on etembus e ogidóc od oicíni on oirátnemoc omoc otelpmoc olpmexe etse acoloc ,ogidóc o meb atnemoc arogA .uonoicnuF .etnelecxE
 * Encrypted Reversed Message: A38331E700D33EE02F18356B17C3EB41D7C988921F5E11515543CD71F7772B3D116CCF949DDCDAF29534EAF98C36589E9D1016FBB9D94D14FD477683154656433244EC59D2460A4012B01BBFFDC68308E1E2B1147F91C97D03BADBFF625B841E9F55D5F02BE130F17643DBAF6EB6C0BFB7CCFC1E31963BA9FC7AC82E7A1049270E5002E88237892853A994960892C3C336E81507F30183CD50DAE8A7B481FF73
 */
class HTTPS {
    fun simulate() {
        val pHex = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371".replace(" ", "")
        val gHex = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5".replace(" ", "")
        val BHex = "35A53342 43D08541 B8B0EAB1 96E3E87F 640676A1 56E12698 4E6929A4 92DE9CCE 0A6D7977 83F783D5 BED5BF85 0D56D1FA F78450BA D90E560C 2F448824 F98D32D7 2EDD7276 086EAFBD B923AAB7 391544FD 02955987 EFED9B76 00C39A05 8D85C142 0691A1A4 4984A814 DE743E9C 4A89DD3A 1C13AA61 91F7DB2D 5AB69425 C4736B9E".replace(" ", "")

        val p = BigInteger(pHex, 16)
        val g = BigInteger(gHex, 16)
        val B = BigInteger(BHex, 16)

        // STEP ONE
        val a = generate_a(p)
        val A = toHex(g.modPow(a, p).toByteArray()).substring(2)
        val V = B.modPow(a, p)
        val S = sha256(V.toByteArray())
        val K = generatePassword(S)

        // STEP TWO
//        val encryptedMsg = "F9260EB71E8185708EACC7739437F1674D86879641DE70B6B90E924BBA4F3A14AA54EFFFEA66703A2B757DFE4A3F8611312FFCFDF99CEC3FCC1B702F0D08A4EA9FA2C2D6667ACD1DC944E42E19CB50D1D14E1E850AB35921E5A8D6D69952CE59226BB849689BF73877B0B1A8C9B3AB13"
        val encryptedMsg = "8BEB2187C844936BAF6E96A77953C827231108AD1D3E59CE8F76368C966A3DE745FF140093E697BBCD675781006B403B2FBBBBE294D8536A8938EE9B159EB8979434CC1EB76FD4CEA070D1343EAF9144D2437F7B56E4A54B41E7850EE46F130CD5465242261AC5E141E4DB37FFD82095601B0B9689672C1B9F62EA9929E559F32CC5077DDAD0C6D239DCAA4C099FDF77930BBF595F96BFC442D0127D4D438D30"
//        val encryptedMsg = "CD1ECCB9EE60C4B409968124DA06B0C30A172085830AD2F0EC76E140ABE88A22"

        val IV = encryptedMsg.take(32)
        val msg = encryptedMsg.takeLast(encryptedMsg.length - 32)
        val decryptedMsg = decryptMessage(msg, fromHexString(K), fromHexString(IV))
        val reversedMsg = decryptedMsg.reversed()
        val encryptedReversedMsg = encryptMessage(reversedMsg, fromHexString(K))

        println("a: $a")
        println("A: $A")
        println("V: $V")
        println("S: ${toHex(S)}")
        println("K: $K")
        println("IV: $IV")
        println("Decrypted Message: $decryptedMsg")
        println("Reversed Message: $reversedMsg")
        println("Encrypted Reversed Message: $encryptedReversedMsg")
    }
    private fun generate_a(p: BigInteger): BigInteger {
//        val randomGenerator = SecureRandom()
//        return BigInteger(p.toString().length, randomGenerator)
        return BigInteger("22548155496845254710235689745815")
    }

    private fun toHex(byteArray: ByteArray): String {
        return byteArray.joinToString(separator = "") { eachByte -> "%02x".format(eachByte).uppercase() }
    }

    private fun sha256(input: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input)
    }

    private fun generatePassword(S: ByteArray): String {
        return toHex(S.take(16).toByteArray())
    }

    private fun decryptMessage(msg: String, K: ByteArray, IV: ByteArray): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val key: SecretKey = SecretKeySpec(K, "AES")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(IV))
        val plainText = cipher.doFinal(fromHexString(msg))
        return String(plainText)
    }

    private fun encryptMessage(msg: String, K: ByteArray): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val key: SecretKey = SecretKeySpec(K, "AES")
        val IV: ByteArray = cipher.parameters.getParameterSpec(IvParameterSpec::class.java).iv
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(IV))
        val cipherText = cipher.doFinal(msg.toByteArray())
        return toHex(IV + cipherText)
    }

    fun fromHexString(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4)
                    + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}