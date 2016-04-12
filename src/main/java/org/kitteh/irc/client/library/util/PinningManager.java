package org.kitteh.irc.client.library.util;

import java.util.Optional;
import java.util.Set;

public interface PinningManager {
    /**
     * @return The current or working hostname.
     */
    Optional<String> getCurrentHostname();

    /**
     * Sets the current or working hostname.
     *
     * @param currentHostname The hostname to use.
     */
    void setCurrentHostname(String currentHostname);

    /**
     * Gets all the pins for the current (working) hostname.
     *
     * @return A set of pin strings (potentially empty).
     */
    Set<String> getPinsForCurrentHostname();

    /**
     * Adds a pin to the map.
     *
     * @param hostname The hostname to pin this to.
     * @param pin      SHA256 hash of SPKI.
     */
    void addPinForHostname(String hostname, String pin);

    /**
     * Clears the pins (if any) attached to the hostname.
     *
     * @param hostname The hostname to clear.
     */
    void clearPinsForHostname(String hostname);

    /**
     * Removes the pin if it's in the set for the given hostname.
     *
     * @param hostname The hostname to remove this pin from.
     * @param pin      The pin to remove.
     */
    void removePinForHostname(String hostname, String pin);
}
