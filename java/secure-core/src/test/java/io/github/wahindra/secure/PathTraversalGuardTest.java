package io.github.wahindra.secure;

import io.github.wahindra.secure.path.PathTraversalException;
import io.github.wahindra.secure.path.PathTraversalGuard;
import io.github.wahindra.secure.path.SafeFileName;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PathTraversalGuardTest {

    @TempDir
    Path tmp;

    @Test
    void resolvesInsideBase() throws IOException {
        PathTraversalGuard guard = PathTraversalGuard.forBaseDirectory(tmp);
        Path p = guard.resolve("reports/2026/q1.pdf");
        assertTrue(p.startsWith(tmp.toRealPath()));
        assertEquals("q1.pdf", p.getFileName().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "../secret.txt", "a/../../secret.txt", "..\\secret.txt", "/etc/passwd", "\\\\server\\share",
            "C:\\Windows\\win.ini", "C:secret", "file.txt::$DATA", "%2e%2e/secret", "%2e%2e%2fsecret",
            "..%c0%afsecret", "report.pdf\u0000.png", "....//secret", "~/.ssh/id_rsa", "", " ", ".. /x", "."
    })
    void rejectsTraversal(String input) throws IOException {
        PathTraversalGuard guard = PathTraversalGuard.forBaseDirectory(tmp);
        assertThrows(PathTraversalException.class, () -> guard.resolve(input));
        assertFalse(guard.isSafe(input));
    }

    @Test
    void rejectsSymlinkEscape() throws IOException {
        Path outside = Files.createTempDirectory("outside");
        Path base = Files.createDirectory(tmp.resolve("base"));
        try {
            Files.createSymbolicLink(base.resolve("link"), outside);
        } catch (IOException | UnsupportedOperationException e) {
            Assumptions.assumeTrue(false, "symlinks need admin rights or developer mode on Windows");
        }
        PathTraversalGuard guard = PathTraversalGuard.forBaseDirectory(base);
        assertThrows(PathTraversalException.class, () -> guard.resolve("link/file.txt"));
    }

    @Test
    void safeFileNames() {
        assertTrue(SafeFileName.isSafe("invoice-2026.pdf"));
        assertFalse(SafeFileName.isSafe("../x.pdf"));
        assertFalse(SafeFileName.isSafe("CON"));
        assertFalse(SafeFileName.isSafe("nul.txt"));
        assertFalse(SafeFileName.isSafe(".htaccess"));
        assertFalse(SafeFileName.isSafe("x.pdf."));
        assertEquals("passwd", SafeFileName.sanitize("../../etc/passwd"));
        assertEquals("win.ini", SafeFileName.sanitize("..\\..\\windows\\win.ini"));
        assertEquals("_CON", SafeFileName.sanitize("CON"));
        assertEquals("file", SafeFileName.sanitize("..."));
        assertEquals("a_b.png", SafeFileName.sanitize("a<b.png"));
        assertEquals("htaccess", SafeFileName.sanitize(".htaccess"));
    }
}
