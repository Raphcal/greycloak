package com.github.raphcal.greycloak.model;

/**
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public enum ResponseMode {
    QUERY('?'),
    FRAGMENT('#');

    public char getStart() {
        return start;
    }

    private final char start;
    private ResponseMode(char start) {
        this.start = start;
    }
}
