/*
 * Tide table for the harbour.
 */
package org.example.harbour;

import java.time.LocalTime;
import java.util.List;
import static java.util.Objects.requireNonNull;

public final class TideTable {
    private final List<LocalTime> highWater;

    public TideTable(List<LocalTime> highWater) {
        this.highWater = requireNonNull(highWater);
    }

    public int count() {
        return highWater.size(); // TODO: include low water
    }
}

interface Tides {
    int count();
}
