package io.github.peerward.peerward.join

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.Result
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.BarcodeFormat
import io.github.peerward.peerward.R
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Camera permission and frames exist only while this explicit scan screen is visible. */
class QrScanActivity : ComponentActivity() {
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val completed = AtomicBoolean(false)
    private lateinit var previewView: PreviewView
    private lateinit var status: TextView
    private val permission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        if (it) startCamera() else finishWithError(ERROR_PERMISSION_DENIED)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        previewView = PreviewView(this)
        status = TextView(this).apply {
            setText(R.string.qr_scan_instruction)
            setPadding(32, 32, 32, 32)
            setBackgroundColor(0xCC000000.toInt())
            setTextColor(0xFFFFFFFF.toInt())
        }
        setContentView(FrameLayout(this).apply {
            addView(previewView, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ))
            addView(status, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        })
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            permission.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        cameraExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            runCatching {
                val provider = future.get()
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                val reader = MultiFormatReader().apply {
                    setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
                }
                analysis.setAnalyzer(cameraExecutor) { image -> analyze(reader, image) }
                provider.unbindAll()
                provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }.onFailure { finishWithError(ERROR_CAMERA_UNAVAILABLE) }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun analyze(reader: MultiFormatReader, image: ImageProxy) {
        try {
            val result = decode(reader, image) ?: return
            val invitation = result.text ?: return
            if (invitation.toByteArray().size > MAX_QR_BYTES) {
                showInvalid(ERROR_PAYLOAD_TOO_LARGE)
                return
            }
            runCatching { JoinBundle.parse(invitation) }
                .onSuccess { finishWithInvitation(invitation) }
                .onFailure { showInvalid(ERROR_INVALID_INVITATION) }
        } finally {
            reader.reset()
            image.close()
        }
    }

    private fun decode(reader: MultiFormatReader, image: ImageProxy): Result? {
        val plane = image.planes.firstOrNull() ?: return null
        val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
        var source: LuminanceSource = PlanarYUVLuminanceSource(
            bytes,
            plane.rowStride,
            image.height,
            0,
            0,
            image.width,
            image.height,
            false,
        )
        repeat((image.imageInfo.rotationDegrees / 90).mod(4)) {
            if (source.isRotateSupported) source = source.rotateCounterClockwise()
        }
        return runCatching { reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))) }
            .getOrNull()
    }

    private fun showInvalid(code: String) {
        runOnUiThread { status.text = getString(R.string.qr_scan_invalid, code) }
    }

    private fun finishWithInvitation(invitation: String) {
        if (!completed.compareAndSet(false, true)) return
        runOnUiThread {
            setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_INVITATION, invitation))
            finish()
        }
    }

    private fun finishWithError(code: String) {
        if (!completed.compareAndSet(false, true)) return
        setResult(Activity.RESULT_CANCELED, Intent().putExtra(EXTRA_ERROR, code))
        finish()
    }

    companion object {
        const val EXTRA_INVITATION = "peerward.invitation"
        const val EXTRA_ERROR = "peerward.scan_error"
        const val ERROR_PERMISSION_DENIED = "camera_permission_denied"
        const val ERROR_CAMERA_UNAVAILABLE = "camera_unavailable"
        const val ERROR_PAYLOAD_TOO_LARGE = "qr_payload_too_large"
        const val ERROR_INVALID_INVITATION = "invalid_invitation"
        private const val MAX_QR_BYTES = 16 * 1024
    }
}
