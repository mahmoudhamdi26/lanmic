package io.lanmic.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.Process
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.math.abs
import kotlin.math.max

class MicService : Service() {
    private var recorder: AudioRecord? = null
    private var socket: WebSocket? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private val runningFlag = AtomicBoolean(false)
    private var worker: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        host = intent?.getStringExtra(EXTRA_HOST) ?: host
        port = intent?.getIntExtra(EXTRA_PORT, port) ?: port
        createChannel()
        val notification = buildNotification("Connecting to $host:$port")
        if (Build.VERSION.SDK_INT >= 30) {
            ServiceCompat.startForeground(
                this,
                NOTIF_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            )
        } else {
            startForeground(NOTIF_ID, notification)
        }
        startStream()
        return START_STICKY
    }

    override fun onDestroy() {
        stopStream()
        super.onDestroy()
    }

    private fun startStream() {
        if (!runningFlag.compareAndSet(false, true)) return
        running = true
        sentKb = 0
        peak = 0
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "lanmic:mic").apply {
            acquire()
        }
        val insecure = trustAllClient()
        val scheme = if (port == 8766) "wss" else "ws"
        val request = Request.Builder().url("$scheme://$host:$port/ws").build()
        socket = insecure.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send("""{"type":"hello","rate":48000,"channels":1}""")
                startRecorder(webSocket)
                notify("Streaming to $host:$port")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                notify("Disconnected: ${t.message}")
                stopSelf()
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                stopSelf()
            }
        })
    }

    private fun startRecorder(webSocket: WebSocket) {
        val rate = 48000
        val min = AudioRecord.getMinBufferSize(
            rate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        val bufferSize = max(min, 1920)
        val format = AudioFormat.Builder()
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setSampleRate(rate)
            .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
            .build()
        val rec = try {
            val builder = AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.UNPROCESSED)
                .setAudioFormat(format)
                .setBufferSizeInBytes(bufferSize)
            val built = builder.build()
            if (built.state != AudioRecord.STATE_INITIALIZED) {
                built.release()
                throw IllegalStateException("uninitialized")
            }
            built
        } catch (_: Exception) {
            AudioRecord(
                MediaRecorder.AudioSource.MIC,
                rate,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                bufferSize
            )
        }
        recorder = rec
        rec.startRecording()
        worker = Thread {
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO)
            val buf = ByteArray(960)
            var sent = 0L
            var ticks = 0
            while (runningFlag.get()) {
                val n = rec.read(buf, 0, buf.size)
                if (n > 0) {
                    ticks += 1
                    if (ticks % 8 == 0) {
                        var localPeak = 0
                        var i = 0
                        while (i + 1 < n) {
                            val s = (buf[i].toInt() and 0xff) or (buf[i + 1].toInt() shl 8)
                            localPeak = max(localPeak, abs(s.toShort().toInt()))
                            i += 2
                        }
                        peak = ((localPeak * 100) / 32767).coerceAtMost(100)
                    }
                    sent += n
                    sentKb = (sent / 1024).toInt()
                    webSocket.send(buf.toByteString(0, n))
                }
            }
        }.also { it.start() }
    }

    private fun stopStream() {
        runningFlag.set(false)
        running = false
        worker?.join(500)
        worker = null
        try { recorder?.stop() } catch (_: Exception) {}
        try { recorder?.release() } catch (_: Exception) {}
        recorder = null
        socket?.close(1000, "stop")
        socket = null
        if (wakeLock?.isHeld == true) wakeLock?.release()
        wakeLock = null
    }

    private fun createChannel() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "LanMic", NotificationManager.IMPORTANCE_LOW)
        )
    }

    private fun buildNotification(text: String): Notification {
        val pending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LanMic")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_mic)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }

    private fun notify(text: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(NOTIF_ID, buildNotification(text))
    }

    private fun trustAllClient(): OkHttpClient {
        val trust = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ssl = SSLContext.getInstance("TLS")
        ssl.init(null, arrayOf(trust), SecureRandom())
        return OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trust)
            .hostnameVerifier { _, _ -> true }
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(20, TimeUnit.SECONDS)
            .socketFactory(object : javax.net.SocketFactory() {
                private val d = javax.net.SocketFactory.getDefault()
                override fun createSocket(): java.net.Socket {
                    val s = d.createSocket()
                    s.tcpNoDelay = true
                    s.trafficClass = 0x10
                    return s
                }
                override fun createSocket(h: String, p: Int) = d.createSocket(h, p).apply { tcpNoDelay = true }
                override fun createSocket(h: String, p: Int, l: java.net.InetAddress, lp: Int) = d.createSocket(h, p, l, lp).apply { tcpNoDelay = true }
                override fun createSocket(h: java.net.InetAddress, p: Int) = d.createSocket(h, p).apply { tcpNoDelay = true }
                override fun createSocket(h: java.net.InetAddress, p: Int, l: java.net.InetAddress, lp: Int) = d.createSocket(h, p, l, lp).apply { tcpNoDelay = true }
            })
            .build()
    }

    companion object {
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val CHANNEL_ID = "lanmic"
        const val NOTIF_ID = 17
        @Volatile var running: Boolean = false
        @Volatile var host: String = "192.168.8.81"
        @Volatile var port: Int = 8767
        @Volatile var sentKb: Int = 0
        @Volatile var peak: Int = 0
    }
}
