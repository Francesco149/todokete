// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// For more information, please refer to <http://unlicense.org/>

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody

const val ServerEndpoint =
  "https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1010"
const val StartupKey = "G5OdK4KdQO5UM2nL"
const val RSAPublicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZUSWq8LCuF2JclEp6uuW9+yddLQvb2420+F8
rxIF8+W53BiF8g9m6nCETdRw7RVnzNABevMndCCTD6oQ6a2w0QpoKeT26578UCWtGp74NGg2Q2fH
YFMAhTytVk48qO4ViCN3snFs0AURU06niM98MIcEUnj9vj6kOBlOGv4JWQIDAQAB
-----END PUBLIC KEY-----"""
const val PackageName = "com.klab.lovelive.allstars"
const val MasterVersion = "646e6e305660c69f"

// md5, sha1, sha256 of the package's signature
// obtained by running https://github.com/warren-bank/print-apk-signature
// on the split apk
val PackageSignatures = arrayOf(
  "3f45f90cbcc718e4b63462baeae90c86",
  "1be2103a6929b38798a29d89044892f3b3934184",
  "1d32dbcf91697d46594ad689d49bb137f65d4bb8f56a26724ae7008648131b82"
)

// md5, sha1, sha256 of libjackpot-core.so
val JackpotSignatures = arrayOf(
  "81ec95e20a695c600375e3b8349722ab",
  "5a3cb86aa9b082d6a1c1dfa6f73dd431d7f14e18",
  "66370b8c96de7266b02bfe17e696d8a61b587656a34b19fbb0b2768a5305dd1d"
).map { it.hexStringToByteArray() }

// md5, sha1, sha256 of libil2cpp.so
val Il2CppSignatures = arrayOf(
  "67f969e32c2d775b35e2f2ad10b423c1",
  "c4387c429c50c4782ab3df409db3abcfa8fadf79",
  "d30568d1057fecb31a16f4062239c1ec65b9c2beab41b836658b637dcb5a51e4"
).map { it.hexStringToByteArray() }

// ------------------------------------------------------------------------

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun ByteArray.xor(other: ByteArray) =
  (zip(other) { a, b -> (a.toInt() xor b.toInt()).toByte() }).toByteArray()

fun String.hexStringToByteArray() =
  chunked(2).map { it.toInt(16).toByte() }.toByteArray()

val kf = KeyFactory.getInstance("RSA")
val keyBytes = Base64.getDecoder().decode(
  RSAPublicKey
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace("\\s+".toRegex(), "")
)
val keySpecX509 = X509EncodedKeySpec(keyBytes)
val pubKey = kf.generatePublic(keySpecX509)

val gson = Gson()
val base64Encoder = Base64.getEncoder()
val base64Decoder = Base64.getDecoder()

fun md5(str: String): String {
  val digest = MessageDigest.getInstance("MD5")
  digest.reset()
  digest.update(str.toByteArray())
  val hash = digest.digest()
  return BigInteger(1, hash).toString(16).padStart(32, '0')
}

fun publicEncrypt(data: ByteArray): ByteArray {
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
  cipher.init(Cipher.ENCRYPT_MODE, pubKey)
  return cipher.doFinal(data)
}

fun hmacSha1(key: ByteArray, data: ByteArray): String {
  val hmacKey = SecretKeySpec(key, "HmacSHA1")
  val hmac = Mac.getInstance("HmacSHA1")
  hmac.init(hmacKey)
  return hmac.doFinal(data).toHexString()
}

// ------------------------------------------------------------------------

var requestId = 0
var sessionKey = StartupKey.toByteArray()

const val WithMasterVersion = 1 shl 1
const val WithTime = 1 shl 2
const val PrintHeaders = 1 shl 3

fun call(
  path: String,
  payload: String,
  flags: Int = 0,
  userId: Int = 0
): String {
  requestId += 1
  var pathWithQuery = path + "?p=a"
  if ((flags and WithMasterVersion) != 0) {
    pathWithQuery += "&mv=$MasterVersion"
  }
  pathWithQuery += "&id=$requestId"
  if (userId != 0) {
    pathWithQuery += "&u=$userId"
  }
  if ((flags and WithTime) != 0) {
    val millitime = System.currentTimeMillis()
    pathWithQuery += "&t=$millitime"
  }
  println("-> POST $pathWithQuery")
  val hashData = pathWithQuery + " " + payload
  val hash = hmacSha1(sessionKey, hashData.toByteArray())
  val json = """[$payload,"$hash"]"""
  println("-> $json")
  val JSON = MediaType.parse("application/json")
  val client = OkHttpClient()
  val request = Request.Builder()
    .url("$ServerEndpoint$pathWithQuery")
    .post(RequestBody.create(JSON, json.toByteArray()))
    .build()
  val response = client.newCall(request).execute()
  if (!response.isSuccessful) {
    println("unexpected code $response")
  }
  if ((flags and PrintHeaders) != 0) {
    val headers = response.headers()
    for (i in 0..headers.size() - 1) {
      val name = headers.name(i)
      val value = headers.value(i)
      println("<- $name: $value")
    }
  }
  val s = response.body()!!.string()
  println("<- $s")
  return s
}

data class StartupRequest(
  val mask: String,
  val resemara_detection_identifier: String,
  val time_difference: Int
)

data class StartupResponse(
  val user_id: Int,
  val authorization_key: String
)

fun startup(randomBytes: ByteArray): StartupResponse? {
  val advertisingId = UUID.randomUUID().toString()
  val resemara = md5(advertisingId + PackageName)
  val maskBytes = publicEncrypt(randomBytes)
  val mask = base64Encoder.encodeToString(maskBytes)
  val result = call(
    path = "/login/startup",
    payload = gson.toJson(StartupRequest(
      mask = mask,
      resemara_detection_identifier = resemara,
      time_difference = 3600
    ), StartupRequest::class.java),
    flags = WithMasterVersion or WithTime
  )
  val array = JsonParser.parseString(result).getAsJsonArray()
  for (x in array) {
    if (x.isJsonObject()) {
      return gson.fromJson(x, StartupResponse::class.java)
    }
  }
  return null
}

data class LoginRequest(
  val user_id: Int,
  val auth_count: Int,
  val mask: String,
  val asset_state: String
)

@ExperimentalUnsignedTypes
fun assetStateLogGenerateV2(randomBytes64: String): String {
  val libHashChar = (randomBytes64[0].toInt() and 1) + 1
  val libHashType = randomBytes64[libHashChar].toInt().rem(3)
  val pkgHashChar = 2 - (randomBytes64[0].toInt() and 1)
  val pkgHashType = randomBytes64[pkgHashChar].toInt().rem(3)
  val xoredHashes =
    JackpotSignatures[libHashType].xor(Il2CppSignatures[libHashType])
      .toHexString()
  val packageSignature = PackageSignatures[pkgHashType]
  val signatures = when (randomBytes64[0].toInt() and 1) {
    0 -> "$xoredHashes-$packageSignature"
    1 -> "$packageSignature-$xoredHashes"
    else -> "$xoredHashes-$packageSignature"
  }
  var xorkey =
    (randomBytes64[0].toByte().toUInt() or
    (randomBytes64[1].toByte().toUInt() shl 8) or
    (randomBytes64[2].toByte().toUInt() shl 16) or
    (randomBytes64[3].toByte().toUInt() shl 24)) xor 0x12d8af36u
  var a = 0u
  var b = 0u
  var c = 0x2bd57287u
  var d = 0u
  var e = 0x202c9ea2u
  var f = 0u
  var g = 0x139da385u
  var h = 0u
  var i = 0u
  var j = 0u
  var k = 0u
  repeat(10) {
    h = g
    i = f
    j = e
    k = d
    g = c
    f = b
    a = ((a shl 11) or (xorkey shr 21)) xor a
    xorkey = (xorkey shl 11) xor xorkey
    c = ((g shr 19) or (k shl 13)) xor xorkey xor g
    c = c xor ((xorkey shr 8) or (a shl 24))
    d = (k shr 19) xor a xor k xor (a shr 8)
    xorkey = j
    a = i
    b = k
    e = h
  }
  val xorBytes = ByteArray(signatures.length)
  for (index in 0..signatures.length - 1) {
    a = g
    xorkey = f
    b = ((i shl 11) or (j shr 21)) xor i
    j = (j shl 11) xor j
    e = ((c shr 19) or (d shl 13)) xor j
    e = e xor c xor ((j shr 8) or (b shl 24))
    xorBytes[index] = e.toByte()
    f = k
    g = c
    k = d
    j = h
    i = xorkey
    c = e
    d = (d shr 19) xor b xor d xor (b shr 8)
    h = a
  }
  return base64Encoder
    .encodeToString(signatures.toByteArray().xor(xorBytes))
}

var authCount = 0

@ExperimentalUnsignedTypes
fun login(userId: Int) {
  authCount += 1
  val randomBytes = Random.nextBytes(32)
  val randomBytes64 = base64Encoder.encodeToString(randomBytes)
  val maskBytes = publicEncrypt(randomBytes)
  val mask = base64Encoder.encodeToString(maskBytes)
  val result = call(
    path = "/login/login",
    payload = gson.toJson(LoginRequest(
      user_id = userId,
      auth_count = authCount,
      mask = mask,
      asset_state = assetStateLogGenerateV2(randomBytes64)
    ), LoginRequest::class.java),
    userId = userId
  )
  val prettyPrint = GsonBuilder().setPrettyPrinting().create()
  val array = JsonParser.parseString(result).getAsJsonArray()
  println(prettyPrint.toJson(array))
}

@ExperimentalUnsignedTypes
fun testAssetState() {
  val randomBytesBase64 = "CB7tjOEZK6IQJrX93O0BuTjM5txYFmFO8sv1Pq9eAcE="
  val generated = assetStateLogGenerateV2(randomBytesBase64)
  val expected = "D9NtY0n3oGxKjhaaJtABDcErt3xQ6kV5gjwD9kmKTG9SprprtHN7Yz" +
    "8vUHfZpisWHG3lgU2Lh43ELGIOWIUKN3S3C8Bx3BVU0w=="
  assert(generated == expected)
}

fun main(args: Array<String>) {
  testAssetState()
  val randomBytes = Random.nextBytes(32)
  val startupResponse = startup(randomBytes)
  println(startupResponse!!)
  val authKey = base64Decoder.decode(startupResponse.authorization_key)
  sessionKey = authKey.xor(randomBytes)
  login(startupResponse.user_id)
}
