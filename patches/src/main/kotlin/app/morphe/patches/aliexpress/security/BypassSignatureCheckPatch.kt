package app.morphe.patches.aliexpress.security

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patches.aliexpress.utils.Constants.COMPATIBILITY_ALIEXPRESS

internal object TamperCheckFingerprint : Fingerprint(
    strings = listOf("may be malicious user illegally tamper data"),
)

val bypassSignatureCheckPatch = bytecodePatch(
    name = "Bypass signature check",
    description = "Bypasses SecurityGuard integrity checks to restore login on patched APKs.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_ALIEXPRESS)

    execute {
        TamperCheckFingerprint.method.apply {
            addInstructions(
                0,
                when (returnType.toString()) {
                    "V" -> "return-void"
                    "Z" -> """
                        const/4 v0, 0x1
                        return v0
                        """.trimIndent()
                    else -> """
                        const/4 v0, 0x0
                        return v0
                        """.trimIndent()
                },
            )
        }
    }
}
