package io.github.wahindra.secure.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Password rules per NIST SP 800-63B / OWASP ASVS: length over composition, a block list of
 * common passwords, no reuse of the user name. Returns violations rather than throwing so the
 * UI can show them all.
 */
public final class PasswordPolicy {

    private static final Set<String> COMMON = new HashSet<String>(Arrays.asList(
            "123456", "123456789", "12345678", "password", "qwerty123", "qwerty", "1234567890", "111111",
            "1234567", "password1", "123123", "abc123", "iloveyou", "admin", "admin123", "welcome",
            "welcome1", "letmein", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
            "passw0rd", "p@ssw0rd", "p@ssword", "changeme", "secret", "trustno1", "qwertyuiop",
            "1q2w3e4r", "zaq12wsx", "password123", "administrator", "root", "toor", "master", "superman",
            "000000", "654321", "666666", "888888", "121212", "asdfghjkl", "michael", "shadow", "starwars"));

    private final int minLength;
    private final int maxLength;

    public PasswordPolicy() {
        this(12, 128);
    }

    public PasswordPolicy(int minLength, int maxLength) {
        this.minLength = minLength;
        this.maxLength = maxLength;
    }

    public List<String> validate(char[] password, String username) {
        List<String> errors = new ArrayList<String>();
        if (password == null || password.length < minLength) {
            errors.add("Password must be at least " + minLength + " characters.");
            return errors;
        }
        if (password.length > maxLength) {
            errors.add("Password must be at most " + maxLength + " characters.");
        }
        String p = new String(password).toLowerCase(Locale.ROOT);
        if (COMMON.contains(p) || COMMON.contains(p.replaceAll("[0-9!@#$%^&*.]+$", ""))) {
            errors.add("Password is too common.");
        }
        if (username != null && username.length() >= 3 && p.contains(username.toLowerCase(Locale.ROOT))) {
            errors.add("Password must not contain the user name.");
        }
        if (isRepetitive(p)) {
            errors.add("Password must not be a repeated or sequential pattern.");
        }
        return errors.isEmpty() ? Collections.<String>emptyList() : errors;
    }

    public boolean isAcceptable(char[] password, String username) {
        return validate(password, username).isEmpty();
    }

    private static boolean isRepetitive(String p) {
        boolean same = true;
        boolean ascending = true;
        for (int i = 1; i < p.length(); i++) {
            same &= p.charAt(i) == p.charAt(0);
            ascending &= p.charAt(i) == p.charAt(i - 1) + 1;
        }
        return same || ascending;
    }
}
