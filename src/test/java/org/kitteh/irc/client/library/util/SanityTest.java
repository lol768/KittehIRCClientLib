package org.kitteh.irc.client.library.util;

import org.junit.Test;

/**
 * Do you know the definition of testing?
 */
public class SanityTest {
    /**
     * Tests nullCheck with valid info.
     */
    @Test
    public void nullCheckPass() {
        Sanity.nullCheck(new Object(), "Pass failed!");
    }

    /**
     * Tests nullCheck with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullCheckFail() {
        Sanity.nullCheck((Object) null, "Failure!");
    }

    /**
     * Tests nullCheck with valid array info.
     */
    @Test
    public void nullCheckArrayPass() {
        Sanity.nullCheck(new Object[]{"meow", "Meow"}, "Pass failed!");
    }

    /**
     * Tests nullCheck with invalid array info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullCheckArrayFail() {
        Sanity.nullCheck((Object[]) null, "Failure!");
    }

    /**
     * Tests nullCheck with invalid array info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullCheckArrayFailElement() {
        Sanity.nullCheck(new Object[]{"meow", null}, "Failure!");
    }

    /**
     * Tests truthiness with valid info.
     */
    @Test
    public void truthPass() {
        Sanity.truthiness(true, "Pass");
    }

    /**
     * Tests truthiness with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void truthFail() {
        Sanity.truthiness(false, "Fail");
    }

    /**
     * Tests safeMessageCheck with valid info.
     */
    @Test
    public void safeMessagePass() {
        Sanity.safeMessageCheck("Meow");
    }

    /**
     * Tests safeMessageCheck with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void safeMessageFailNull() {
        Sanity.safeMessageCheck(null);
    }

    /**
     * Tests safeMessageCheck with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void safeMessageFailLF() {
        Sanity.safeMessageCheck("Me\now");
    }

    /**
     * Tests safeMessageCheck with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void safeMessageFailCR() {
        Sanity.safeMessageCheck("Me\row");
    }

    /**
     * Tests safeMessageCheck with invalid info.
     */
    @Test(expected = IllegalArgumentException.class)
    public void safeMessageFailNul() {
        Sanity.safeMessageCheck("Me\0ow");
    }
}
