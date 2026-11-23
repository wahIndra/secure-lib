package io.github.wahindra.secure.integrity;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Allowlist-based Java deserialization (insecure deserialization / gadget chains). Works on
 * Java 8 without {@code ObjectInputFilter}. Prefer JSON with explicit DTOs; use this only
 * when native serialization cannot be avoided.
 *
 * <pre>
 * try (ObjectInputStream in = new SafeObjectInputStream(stream, "com.acme.dto.", "java.lang.String")) { ... }
 * </pre>
 */
public final class SafeObjectInputStream extends ObjectInputStream {

    private static final Set<String> ALWAYS_ALLOWED = new LinkedHashSet<String>(Arrays.asList(
            "java.lang.String", "java.lang.Number", "java.lang.Integer", "java.lang.Long", "java.lang.Short",
            "java.lang.Byte", "java.lang.Double", "java.lang.Float", "java.lang.Boolean", "java.lang.Character",
            "java.lang.Enum", "java.math.BigDecimal", "java.math.BigInteger", "java.util.Date"));

    private final Set<String> allowed;

    /**
     * @param allowedClassesOrPackages fully-qualified class names, or package prefixes ending with '.'
     */
    public SafeObjectInputStream(InputStream in, String... allowedClassesOrPackages) throws IOException {
        super(in);
        Set<String> s = new LinkedHashSet<String>(ALWAYS_ALLOWED);
        s.addAll(Arrays.asList(allowedClassesOrPackages));
        this.allowed = Collections.unmodifiableSet(s);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();
        String element = name;
        while (element.startsWith("[")) {
            element = element.substring(1);
        }
        if (element.startsWith("L") && element.endsWith(";")) {
            element = element.substring(1, element.length() - 1);
        }
        boolean primitiveArray = name.startsWith("[") && element.length() == 1;
        if (!primitiveArray && !isAllowed(element)) {
            throw new InvalidClassException(name, "class not in deserialization allowlist");
        }
        return super.resolveClass(desc);
    }

    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws IOException {
        throw new InvalidClassException("proxy", "proxy classes are not allowed");
    }

    private boolean isAllowed(String className) {
        if (allowed.contains(className)) {
            return true;
        }
        for (String a : allowed) {
            if (a.endsWith(".") && className.startsWith(a)) {
                return true;
            }
        }
        return false;
    }
}
