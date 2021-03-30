package com.example.nativec

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Example of a call to a native method
        findViewById<TextView>(R.id.sample_text).text = stringFromJNI()
        Log.d("test", "test ${"Datakjhk".toByteArray().toHexString()} key=${"aaa".toByteArray().toHexString()}")
//        val enc = encodeAES256gcm("aaa".toByteArray(), "Data".toByteArray())
//        Log.d("Andreas", "encode ${enc.toHexString()}")
//
//        val dec = decodeAES256gcm("aaa".toByteArray(), enc)
//        Log.d("Andreas", "decode ${dec.toHexString()}")

//        Log.d("Andreas", "param AES ${"aaa".toByteArray().toHexString()} ${"crn".toByteArray().toHexString()} ${"Data".toByteArray().toHexString()}")
        val enc2 = encodeAES256("4790731b1ec79ccaff06cc86fd67e95b".hexStringToByteArray(), "564371fd50e9edd9233a4286f5ac3f12".hexStringToByteArray(), "Datakjhk".toByteArray())
        Log.d("Andreas", "encode ${enc2.toHexString()}")

        val crn = "564371fd50e9edd9233a4286f5ac3f12".hexStringToByteArray()

        Log.d("Andreas", "start enc")
        val tesmpb = encodeRSAPubKey("E9E5884B7A4298BD1BDEACFDE5394EA6D7721D0DD7CC07A7956E8C45CBA0CF3FC150C9C7B818F651616DABE05D62BB33F40D1B61AE208055C2DD2610CEAB995497E78A4E705CB4AB1472C9DFAFDB2C19B9D113592EFD63191A8BFA6C6B00A9954ADC95CCF3D5926C40C8304B637427C10945DEFB8A64EE26D70A732ECF7C043F8CF0B2FC08D5F075361734D3CC131C4215C55D36DC8B2EE61F4455E2375835A7E96B68321B6577DA963A2C29B2DB538E8C93579C37FE6BD509E57D44E946C9C4EF99DCDCCECE509342F45FDA7EB23CF75E4CB17DB8A3CC7000610D322FDCD49F759864153AB7A16DE822162C38D785212875F9B5A42CFBE83FBFC58893793775",
         "00F68B", enc2)
//     00 ff ff ff ff
        // 616e6472656173
        // 616e6472656173
       Log.d("Andreas", "bio ${tesmpb.toBase64Str()} ${tesmpb.size}")

//        val abc = encodeRSAPubKey("E9E5884B7A4298BD1BDEACFDE5394EA6D7721D0DD7CC07A7956E8C45CBA0CF3FC150C9C7B818F651616DABE05D62BB33F40D1B61AE208055C2DD2610CEAB995497E78A4E705CB4AB1472C9DFAFDB2C19B9D113592EFD63191A8BFA6C6B00A9954ADC95CCF3D5926C40C8304B637427C10945DEFB8A64EE26D70A732ECF7C043F8CF0B2FC08D5F075361734D3CC131C4215C55D36DC8B2EE61F4455E2375835A7E96B68321B6577DA963A2C29B2DB538E8C93579C37FE6BD509E57D44E946C9C4EF99DCDCCECE509342F45FDA7EB23CF75E4CB17DB8A3CC7000610D322FDCD49F759864153AB7A16DE822162C38D785212875F9B5A42CFBE83FBFC58893793775",
//         "00F68B", "encj2".toByteArray())

//        Log.d("Andreas", "start enc")
        val crnenc = encodeRSAPubKey("E9E5884B7A4298BD1BDEACFDE5394EA6D7721D0DD7CC07A7956E8C45CBA0CF3FC150C9C7B818F651616DABE05D62BB33F40D1B61AE208055C2DD2610CEAB995497E78A4E705CB4AB1472C9DFAFDB2C19B9D113592EFD63191A8BFA6C6B00A9954ADC95CCF3D5926C40C8304B637427C10945DEFB8A64EE26D70A732ECF7C043F8CF0B2FC08D5F075361734D3CC131C4215C55D36DC8B2EE61F4455E2375835A7E96B68321B6577DA963A2C29B2DB538E8C93579C37FE6BD509E57D44E946C9C4EF99DCDCCECE509342F45FDA7EB23CF75E4CB17DB8A3CC7000610D322FDCD49F759864153AB7A16DE822162C38D785212875F9B5A42CFBE83FBFC58893793775",
            "00F68B", crn)
////
//            //if (crn!=null)
            Log.d("Andreas", "encCrn ${crnenc.toBase64Str()} ${crnenc.size} -- ${"andreas".toByteArray().toHexString()}")

        Log.d("Andreas", "Combine enc")
        combineEncode("4790731b1ec79ccaff06cc86fd67e95b".hexStringToByteArray(), "564371fd50e9edd9233a4286f5ac3f12".hexStringToByteArray(),"E9E5884B7A4298BD1BDEACFDE5394EA6D7721D0DD7CC07A7956E8C45CBA0CF3FC150C9C7B818F651616DABE05D62BB33F40D1B61AE208055C2DD2610CEAB995497E78A4E705CB4AB1472C9DFAFDB2C19B9D113592EFD63191A8BFA6C6B00A9954ADC95CCF3D5926C40C8304B637427C10945DEFB8A64EE26D70A732ECF7C043F8CF0B2FC08D5F075361734D3CC131C4215C55D36DC8B2EE61F4455E2375835A7E96B68321B6577DA963A2C29B2DB538E8C93579C37FE6BD509E57D44E946C9C4EF99DCDCCECE509342F45FDA7EB23CF75E4CB17DB8A3CC7000610D322FDCD49F759864153AB7A16DE822162C38D785212875F9B5A42CFBE83FBFC58893793775",
            "00F68B", "data".toByteArray())
//     00 ff ff ff ff
        // 616e6472656173
        // 616e6472656173
        Log.d("Andreas", "combine ${enc1?.toBase64Str()} == ${this.enc2?.toBase64Str()}")
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */

    private var enc1: ByteArray? = null
    private val enc2: ByteArray? = null

    external fun stringFromJNI(): String
    external fun encodeAES256gcm(key: ByteArray, src: ByteArray): ByteArray
    external fun decodeAES256gcm(key: ByteArray, enc: ByteArray): ByteArray
    external fun encodeAES256(srn: ByteArray, crn: ByteArray, src: ByteArray): ByteArray
    external fun encodeRSAPubKey(mod: String, exp: String, data: ByteArray): ByteArray
    external fun combineEncode(srn: ByteArray, crn: ByteArray, mod: String, exp: String, data: ByteArray)


    companion object {
        // Used to load the 'native-lib' library on application startup.
        init {
            System.loadLibrary("crypto")
            System.loadLibrary("ssl")

            System.loadLibrary("native-lib")

//            System.loadLibrary("crypto");
        }
    }

    fun String.hexStringToByteArray() = ByteArray(this.length / 2) { this.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
    fun ByteArray.toBase64Str(): String = String(Base64.encode(this, Base64.DEFAULT))
}