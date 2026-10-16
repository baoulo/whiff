// Harbour model
import Foundation
import SwiftUI

public struct Boat: Identifiable {
    public let id = UUID()
    public var name: String
}

final class Registry {
    private(set) var boats: [Boat] = []
    func add(_ boat: Boat) { boats.append(boat) }
}

protocol Moorable {
    var berth: Int { get }
}
