package io.github.wahindra.secure.path;

import io.github.wahindra.secure.detect.InputNormalizer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Resolves user-supplied relative paths inside a fixed base directory and refuses anything
 * that escapes it: ../ segments, encoded traversal, absolute and UNC paths, drive letters,
 * NTFS streams, null bytes and symlinks pointing outside the base.
 *
 * <pre>
 * PathTraversalGuard uploads = PathTraversalGuard.forBaseDirectory(Paths.get("/srv/app/uploads"));
 * Path file = uploads.resolve(request.getParameter("name"));   // throws PathTraversalException
 * </pre>
 */
public final class PathTraversalGuard {

    private final Path base;

    private PathTraversalGuard(Path base) {
        this.base = base;
    }

    /** The base directory must exist; its real path (symlinks resolved) becomes the boundary. */
    public static PathTraversalGuard forBaseDirectory(Path baseDirectory) throws IOException {
        Path real = baseDirectory.toAbsolutePath().normalize().toRealPath();
        if (!Files.isDirectory(real)) {
            throw new IOException("Base path is not a directory: " + real);
        }
        return new PathTraversalGuard(real);
    }

    public Path getBaseDirectory() {
        return base;
    }

    /**
     * Returns the absolute path for {@code userPath} inside the base directory.
     *
     * @throws PathTraversalException if the path is unsafe or leaves the base directory
     */
    public Path resolve(String userPath) {
        String checked = validateRelative(userPath);
        Path resolved = base;
        for (String segment : checked.split("[/\\\\]+")) {
            if (!segment.isEmpty() && !".".equals(segment)) {
                resolved = resolved.resolve(segment);
            }
        }
        resolved = resolved.normalize();
        if (!resolved.startsWith(base) || resolved.equals(base)) {
            throw new PathTraversalException("path escapes base directory");
        }
        assertNoSymlinkEscape(resolved);
        return resolved;
    }

    /** Like {@link #resolve(String)} but returns {@code false} instead of throwing. */
    public boolean isSafe(String userPath) {
        try {
            resolve(userPath);
            return true;
        } catch (PathTraversalException e) {
            return false;
        }
    }

    private static String validateRelative(String userPath) {
        if (userPath == null || userPath.trim().isEmpty()) {
            throw new PathTraversalException("empty path");
        }
        if (userPath.length() > 4096) {
            throw new PathTraversalException("path too long");
        }
        // Check the decoded form too: a layer below (proxy, framework, file API) may decode
        // %2e%2e%2f before the file system sees it.
        String decoded = InputNormalizer.decode(userPath);
        for (String candidate : new String[] {userPath, decoded}) {
            if (candidate.indexOf('\0') >= 0) {
                throw new PathTraversalException("null byte in path");
            }
            if (candidate.indexOf(':') >= 0) {
                throw new PathTraversalException("drive letter, scheme or alternate data stream in path");
            }
            if (candidate.startsWith("/") || candidate.startsWith("\\") || candidate.startsWith("~")) {
                throw new PathTraversalException("absolute path");
            }
            for (String segment : candidate.split("[/\\\\]+")) {
                if (segment.length() >= 2 && segment.replace(".", "").trim().isEmpty()) {
                    throw new PathTraversalException("traversal segment");
                }
            }
        }
        return userPath;
    }

    private void assertNoSymlinkEscape(Path resolved) {
        // Walk up to the deepest part of the path that exists and check its real location.
        Path existing = resolved;
        while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            existing = existing.getParent();
        }
        if (existing == null) {
            throw new PathTraversalException("path escapes base directory");
        }
        try {
            if (!existing.toRealPath().startsWith(base)) {
                throw new PathTraversalException("symlink escapes base directory");
            }
        } catch (IOException e) {
            throw new PathTraversalException("cannot resolve real path");
        }
    }
}
