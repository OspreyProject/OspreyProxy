package net.foulest.ospreyproxy.updates;

import org.jspecify.annotations.NonNull;

/**
 * The computed integrity metadata for a CRX on disk.
 *
 * @param sha256 The lowercase hex SHA-256 of the file.
 * @param size The file size in bytes.
 * @param modifiedMillis The file modification time used to invalidate the cache.
 */
public record CRXMeta(@NonNull String sha256, long size, long modifiedMillis) {

}
