/*
 * * Copyright (C) 2013-2016 Matt Baxter http://kitteh.org
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.kitteh.irc.client.library.util;

import io.netty.handler.ssl.util.SimpleTrustManagerFactory;
import io.netty.util.internal.EmptyArrays;
import org.kitteh.irc.client.library.Client;

import javax.annotation.Nonnull;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A trust manager factory that allows for pinning SHA256 hashes of SPKIs.
 *
 * @see Client.Builder#secureTrustManagerFactory(TrustManagerFactory)
 */
public final class PinningTrustManagerFactory extends SimpleTrustManagerFactory implements PinningManager {

    private MessageDigest digest;
    private Map<String, Set<String>> pins = new HashMap<>();
    private String currentHostname;

    protected PinningTrustManagerFactory() throws NoSuchAlgorithmException {
        super("Pinning");
        this.digest = MessageDigest.getInstance("SHA-256");
    }

    public Optional<String> getCurrentHostname() {
        return Optional.ofNullable(this.currentHostname);
    }

    public void setCurrentHostname(String currentHostname) {
        this.currentHostname = currentHostname;
    }

    public Set<String> getPinsForCurrentHostname() {
        return this.pins.getOrDefault(this.currentHostname, Collections.emptySet());
    }

    /**
     * Adds a pin to the map.
     *
     * @param hostname The hostname to pin this to.
     * @param pin      SHA256 hash of SPKI.
     */
    @Override
    public void addPinForHostname(String hostname, String pin) {
        Set<String> currentPins = this.pins.getOrDefault(hostname, Collections.emptySet());
        currentPins.add(pin);
        this.pins.put(hostname, currentPins);
    }

    /**
     * Clears the pins (if any) attached to the hostname.
     *
     * @param hostname The hostname to clear.
     */
    @Override
    public void clearPinsForHostname(String hostname) {
        this.pins.remove(hostname);
    }

    /**
     * Removes the pin if it's in the set for the given hostname.
     *
     * @param hostname The hostname to remove this pin from.
     * @param pin      The pin to remove.
     */
    @Override
    public void removePinForHostname(String hostname, String pin) {
        Set<String> currentPins = this.pins.getOrDefault(hostname, Collections.emptySet());
        currentPins.remove(pin);
        this.pins.put(hostname, currentPins);
    }

    private class PinningManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String s) {
            // NOOP
        }

        @Override
        public void checkServerTrusted(@Nonnull X509Certificate[] chain, @Nonnull String authType) throws CertificateException {
            Set<String> pins = PinningTrustManagerFactory.this.getPinsForCurrentHostname();
            boolean atLeastOneTrusted = false;
            for (X509Certificate cert : chain) {
                // Consider example chain
                // TODO: Check validity of current cert (not expired)
                // TODO: Check revocation status?
                // TODO: Ensure this cert is signed by the next cert in the chain

                byte[] spki = cert.getPublicKey().getEncoded();
                String pinStr = Base64.getEncoder().encodeToString(spki);
                if (pins.contains(pinStr)) {
                    atLeastOneTrusted = true;
                    break;
                }
            }

            if (!atLeastOneTrusted) {
                throw new CertificateException("No pinned certificates in chain");
            }
        }

        @Nonnull
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return EmptyArrays.EMPTY_X509_CERTIFICATES;
        }

        @Nonnull
        @Override
        public String toString() {
            return new ToStringer(this).toString();
        }
    }

    private final TrustManager trustManager = new PinningManager();

    @Nonnull
    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[]{this.trustManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore) throws Exception {
        // NOOP
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {
        // NOOP
    }
}
