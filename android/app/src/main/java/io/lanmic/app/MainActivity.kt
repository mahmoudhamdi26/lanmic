package io.lanmic.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import io.lanmic.app.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val handler = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            binding.status.text = if (MicService.running) "Live" else "Idle"
            binding.status.setTextColor(
                if (MicService.running) 0xFF06281C.toInt() else 0xFFF5C14A.toInt()
            )
            binding.start.text = if (MicService.running) "Stop" else "Start"
            binding.level.progress = MicService.peak
            binding.hint.text = if (MicService.running) {
                "Streaming ${MicService.sentKb} KB to ${MicService.host}:${MicService.port}"
            } else {
                "Use port 8767 (plain WebSocket). Grant microphone permission, then tap Start."
            }
            handler.postDelayed(this, 200)
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { granted ->
        if (granted.values.all { it }) startService()
        else Toast.makeText(this, "Microphone permission is required", Toast.LENGTH_LONG).show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val prefs = getSharedPreferences("lanmic", MODE_PRIVATE)
        binding.host.setText(prefs.getString("host", "192.168.8.81"))
        binding.port.setText(prefs.getString("port", "8767"))
        binding.start.setOnClickListener {
            if (MicService.running) {
                stopService(Intent(this, MicService::class.java))
            } else {
                prefs.edit()
                    .putString("host", binding.host.text.toString().trim())
                    .putString("port", binding.port.text.toString().trim())
                    .apply()
                ensurePermissions()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }

    private fun ensurePermissions() {
        val needed = mutableListOf(Manifest.permission.RECORD_AUDIO)
        if (Build.VERSION.SDK_INT >= 33) needed += Manifest.permission.POST_NOTIFICATIONS
        val missing = needed.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) startService()
        else permissionLauncher.launch(missing.toTypedArray())
    }

    private fun startService() {
        val host = binding.host.text.toString().trim()
        val port = binding.port.text.toString().trim().toIntOrNull() ?: 8767
        if (host.isEmpty()) {
            Toast.makeText(this, "Enter the PC IP address", Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(this, MicService::class.java).apply {
            putExtra(MicService.EXTRA_HOST, host)
            putExtra(MicService.EXTRA_PORT, port)
        }
        ContextCompat.startForegroundService(this, intent)
    }
}
