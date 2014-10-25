/**
 *
 * The MIT License
 *
 * Copyright (c) 2011 the original author or authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.googlecode.charts4j;

/**
 * Enumeration for specifying legend position.
 *
 * @author Julien Chastang (julien.c.chastang at gmail dot com)
 *
 */
public enum LegendPosition {
    /** Horizontal legend position at top. **/
    TOP("t"),

    /** Vertical legend position at top. **/
    TOP_VERTICAL("tv"),

    /** Horizontal legend position at bottom. **/
    BOTTOM("b"),

    /** Vertical legend position at bottom. **/
    BOTTOM_VERTICAL("bv"),

    /** Vertical legend position at right. **/
    RIGHT("r"),

    /** Vertical legend position at left. **/
    LEFT("l");

    /** String for Google Chart API. **/
    private final String legendPosition;

    /**
     * Constructor.
     * @param legendPosition String for Google Chart API
     */
    private LegendPosition(final String legendPosition) {
        this.legendPosition = legendPosition;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return legendPosition;
    }
}
