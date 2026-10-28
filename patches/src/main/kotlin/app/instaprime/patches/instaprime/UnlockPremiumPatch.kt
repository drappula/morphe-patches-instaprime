package app.instaprime.patches.instaprime

import app.instaprime.patches.shared.Constants.COMPATIBILITY_INSTAPRIME
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.rawResourcePatch
import java.io.File
import java.io.RandomAccessFile

/**
 * Native library that contains the subscription check. InstaPrime only ships arm64-v8a code.
 */
private const val PRIMEMODS_LIBRARY = "lib/arm64-v8a/libprimemods.so"

/**
 * `SubscriptionManager` reads the stored subscription expiry from a SharedPreferences key. The
 * obfuscator turns the 64 bit string id of that key into instructions that build the id in a
 * register, which ends with `movk xN, #0xa4c6, lsl #32`. That instruction is used to find the
 * check independently of where the library places the function.
 */
private const val EXPIRY_KEY_IMM16 = 0xA4C6

/** `movk xN, #imm16, lsl #32` with `imm16` cleared. */
private const val MOVK_64_LSL_32 = 0xF2C00000.toInt()

/** Keeps the opcode and the shift, clears the immediate and the destination register. */
private const val MOVK_IMM16_MASK = 0xFFE00000.toInt()

/** `mov w0, #1`, executed when the subscription is missing or expired. */
private const val RETURN_EXPIRED = 0x52800020

/** `mov w0, #0`, which reports an active subscription. */
private const val RETURN_NOT_EXPIRED = 0x52800000

/**
 * How far after the key construction the `mov w0, #1` of the expired branch may be.
 */
private const val MAX_GATE_DISTANCE = 4096

/**
 * `movk xN, #0x39e8, lsl #32` — the string id of `not_premium_user_title`
 * ("You're NOT Premium User"). The premium tab builds this id only inside the branch that shows
 * the non-premium title, so it identifies that branch independently of library layout.
 */
private const val NOT_PREMIUM_TITLE_IMM16 = 0x39E8

/** AArch64 `nop`. Replaces the premium-tab gate so it can never branch to the NOT premium title. */
private const val AARCH64_NOP = 0xD503201F.toInt()

/** `b.le` — B.cond with condition LE. */
private const val B_LE = 0x5400000D
private const val B_LE_MASK = 0xFF00001F.toInt()

/** How far before the `not_premium_user_title` key the gate `b.le` may be. */
private const val MAX_TAB_GATE_DISTANCE = 0x400

private const val CHUNK_SIZE = 1 shl 20

@Suppress("unused")
val unlockPremiumPatch = rawResourcePatch(
    name = "Unlock premium",
    description = "Unlocks the premium subscription by making the subscription check " +
        "always report an active subscription.",
) {
    compatibleWith(COMPATIBILITY_INSTAPRIME)

    execute {
        if (listApkEntries("lib/").none { it == PRIMEMODS_LIBRARY }) {
            throw PatchException(
                "The APK does not contain $PRIMEMODS_LIBRARY. " +
                    "Only the arm64-v8a APK is supported."
            )
        }

        val library = get(PRIMEMODS_LIBRARY)

        val keyOffsets = findExpiryKeyInstructions(library)
        if (keyOffsets.isEmpty()) {
            throw PatchException(
                "$PRIMEMODS_LIBRARY does not contain the subscription check. " +
                    "The app version is not supported."
            )
        }

        val returnOffsets = keyOffsets
            .mapNotNull { findExpiredReturn(library, it) }
            .distinct()

        val returnOffset = returnOffsets.singleOrNull()
            ?: throw PatchException(
                "Expected exactly one subscription check in $PRIMEMODS_LIBRARY, " +
                    "found ${returnOffsets.size}. The app version is not supported."
            )

        patchWord(library, returnOffset, RETURN_NOT_EXPIRED)

        // The premium screen decides its title with a separate native check:
        // `PremiumActivity.lambda$updateUnlockInfo$0` builds the `not_premium_user_title` string
        // id and `b.le`s into it when the stored unlock expiry has passed. Removing that branch
        // tells the screen it is always premium, independently of the server status response.
        val tabKeyOffsets = findMovkImm32Instructions(library, NOT_PREMIUM_TITLE_IMM16)
        val tabKeyOffset = tabKeyOffsets.singleOrNull()
            ?: throw PatchException(
                "Expected exactly one premium-tab gate in $PRIMEMODS_LIBRARY, " +
                    "found ${tabKeyOffsets.size}. The app version is not supported."
            )

        val tabGateOffset = findTabGate(library, tabKeyOffset)
            ?: throw PatchException(
                "Could not locate the premium-tab gate in $PRIMEMODS_LIBRARY. " +
                    "The app version is not supported."
            )

        patchWord(library, tabGateOffset, AARCH64_NOP)
    }
}

/**
 * Finds every `movk xN, #0xa4c6, lsl #32` instruction in [library]. These build the string id of
 * the SharedPreferences key that stores the subscription expiry.
 */
private fun findExpiryKeyInstructions(library: File): List<Long> =
    findMovkImm32Instructions(library, EXPIRY_KEY_IMM16)

/**
 * Finds every `movk xN, #imm16, lsl #32` instruction in [library]. These build the 64 bit string
 * ids of obfuscated strings, so the immediate identifies a specific string independently of where
 * the obfuscator placed the function.
 */
private fun findMovkImm32Instructions(library: File, imm16: Int): List<Long> {
    val offsets = mutableListOf<Long>()
    val buffer = ByteArray(CHUNK_SIZE)

    RandomAccessFile(library, "r").use { file ->
        val length = file.length()
        var offset = 0L

        while (offset < length) {
            file.seek(offset)
            val read = file.read(buffer)
            if (read < 4) break

            var index = 0
            while (index + 4 <= read) {
                val word = readWord(buffer, index)
                if ((word and MOVK_IMM16_MASK) == MOVK_64_LSL_32 &&
                    (word ushr 5) and 0xFFFF == imm16
                ) {
                    offsets += offset + index
                }
                index += 4
            }

            // Advance in whole instructions so every word stays 4 byte aligned.
            offset += read.toLong() and 3L.inv()
        }
    }

    return offsets
}

/**
 * Finds the `b.le` that jumps into the NOT premium branch of the premium screen, looking a short
 * distance before the `not_premium_user_title` key construction at [notPremiumTitleOffset]. The
 * branch target lands on the start of that branch, just before the key.
 */
private fun findTabGate(library: File, notPremiumTitleOffset: Long): Long? {
    val start = maxOf(0L, notPremiumTitleOffset - MAX_TAB_GATE_DISTANCE)
    val buffer = ByteArray((notPremiumTitleOffset - start).toInt())

    RandomAccessFile(library, "r").use { file ->
        file.seek(start)
        val read = file.read(buffer)
        if (read < 4) return null

        val minTarget = notPremiumTitleOffset - MAX_TAB_GATE_DISTANCE / 2
        val gateCandidates = mutableListOf<Long>()
        var index = 0
        while (index + 4 <= read) {
            val word = readWord(buffer, index)
            if (word and B_LE_MASK == B_LE) {
                val address = start + index
                val target = branchTarget(address, word)
                if (target in minTarget..notPremiumTitleOffset) {
                    gateCandidates += address
                }
            }
            index += 4
        }

        return gateCandidates.singleOrNull()
    }
}

/** Computes the target of a B.cond at [address] with encoding [word]. */
private fun branchTarget(address: Long, word: Int): Long {
    var imm19 = (word ushr 5) and 0x7FFFF
    if (imm19 and 0x40000 != 0) {
        imm19 -= 0x80000
    }
    return address + (imm19 shl 2)
}

/**
 * Finds the `mov w0, #1` that the subscription check executes when the subscription is missing or
 * expired, looking only a short distance after [start].
 */
private fun findExpiredReturn(library: File, start: Long): Long? {
    val buffer = ByteArray(MAX_GATE_DISTANCE)

    RandomAccessFile(library, "r").use { file ->
        file.seek(start)
        val read = file.read(buffer)
        if (read < 8) return null

        // Skip the key construction instruction itself.
        var index = 4
        while (index + 4 <= read) {
            if (readWord(buffer, index) == RETURN_EXPIRED) return start + index
            index += 4
        }
    }

    return null
}

private fun readWord(buffer: ByteArray, index: Int): Int =
    (buffer[index].toInt() and 0xFF) or
        ((buffer[index + 1].toInt() and 0xFF) shl 8) or
        ((buffer[index + 2].toInt() and 0xFF) shl 16) or
        ((buffer[index + 3].toInt() and 0xFF) shl 24)

private fun patchWord(library: File, offset: Long, word: Int) {
    RandomAccessFile(library, "rw").use { file ->
        file.seek(offset)
        file.write(
            byteArrayOf(
                word.toByte(),
                (word ushr 8).toByte(),
                (word ushr 16).toByte(),
                (word ushr 24).toByte()
            )
        )

        file.seek(offset)
        val patched = ByteArray(4)
        file.readFully(patched)
        if (readWord(patched, 0) != word) {
            throw PatchException(
                "Failed to patch $PRIMEMODS_LIBRARY at 0x${offset.toString(16)}."
            )
        }
    }
}
