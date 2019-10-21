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

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
fun ByteArray.xor(other: ByteArray) =
  (zip(other) { a, b -> (a.toInt() xor b.toInt()).toByte() }).toByteArray()

fun hmacSha1(key: ByteArray, data: ByteArray): String {
  val hmacKey = SecretKeySpec(key, "HmacSHA1")
  val hmac = Mac.getInstance("HmacSHA1")
  hmac.init(hmacKey)
  return hmac.doFinal(data).toHexString()
}

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

var authCount = 0

fun login(userId: Int) {
  authCount += 1
  val randomBytesBase64 = "+zuyNj+IFhSydzEMTHnrBCyUO0b3CvQt5nOWwxpNKcE="
  val randomBytes = base64Decoder.decode(randomBytesBase64)
  val maskBytes = publicEncrypt(randomBytes)
  val mask = base64Encoder.encodeToString(maskBytes)
  val result = call(
    path = "/login/login",
    payload = gson.toJson(LoginRequest(
      user_id = userId,
      auth_count = authCount,
      mask = mask,
      asset_state = "OqwKkOuhtlyuSzCj95pXUjtEo65SuYtUI3OlrxWWSjz7IEyicA" +
        "MR7/IWuc822gc2cQXHjHY2ASHjQFfdONJNOU5gMM5w4g3Dj2K+iv1HDPZTAdtd" +
        "8BURk7Iu+HVqxACI2g=="
    ), LoginRequest::class.java),
    userId = userId
  )
  val prettyPrint = GsonBuilder().setPrettyPrinting().create()
  val array = JsonParser.parseString(result).getAsJsonArray()
  println(prettyPrint.toJson(array))
}

fun main(args: Array<String>) {
  val randomBytes = Random.nextBytes(32)
  val startupResponse = startup(randomBytes)
  println(startupResponse!!)
  val authKey = base64Decoder.decode(startupResponse.authorization_key)
  println(authKey.toHexString())
  println(randomBytes.toHexString())
  sessionKey = authKey.xor(randomBytes)
  println(sessionKey.toHexString())
  login(startupResponse.user_id)
}
