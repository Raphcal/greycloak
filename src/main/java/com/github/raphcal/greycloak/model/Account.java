package com.github.raphcal.greycloak.model;

import java.util.List;
import java.util.Map;

/**
 * Account.
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public class Account {

    /**
     * Username.
     */
    private String username;

    /**
     * Password.
     */
    private String password;

    /**
     * First name.
     */
    private String firstName;

    /**
     * Last name.
     */
    private String lastName;

    /**
     * Email address.
     */
    private String email;

    /**
     * <code>true</code> if the email address has been verified,
     * <code>false</code> otherwise.
     */
    private boolean emailVerified;

    /**
     * Other attributes. May include creation timestamps, LDAP values and so on.
     */
    private Map<String, List<String>> attributes;

    public Account() {
        // Empty.
    }

    public Account(String username, String password, String firstName, String lastName, String email, boolean emailVerified, Map<String, List<String>> attributes) {
        this.username = username;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.emailVerified = emailVerified;
        this.attributes = attributes;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Map<String, List<String>> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, List<String>> attributes) {
        this.attributes = attributes;
    }

}
