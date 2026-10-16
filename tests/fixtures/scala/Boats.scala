package org.example.harbour

import scala.collection.mutable
import java.time.Instant

case class Boat(name: String, lengthM: Double)

object Registry {
  private val boats = mutable.Buffer[Boat]()
  def add(b: Boat): Unit = boats += b
  def count: Int = boats.size
}

trait Moored { def berth: Int }
