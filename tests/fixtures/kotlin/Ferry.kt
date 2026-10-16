package org.example.harbour

import kotlinx.coroutines.delay
import java.time.Duration

/** A ferry that crosses the harbour. */
data class Ferry(val name: String, val seats: Int)

object Timetable {
    val crossing: Duration = Duration.ofMinutes(20)
}

suspend fun sail(ferry: Ferry) {
    delay(1000)
    println("${ferry.name} sailed")
}

fun main() = println(Ferry("Swift", 120))
