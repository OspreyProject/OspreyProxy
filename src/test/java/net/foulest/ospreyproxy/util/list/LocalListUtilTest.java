/*
 * Copyright (C) 2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util.list;

import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.NetworkUtil;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import sun.misc.Unsafe;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

class LocalListUtilTest {

    @TempDir
    Path temporaryDirectory;

    private Map<Descriptor, AtomicReference<ListSnapshot>> savedStateMap;
    private Map<Descriptor, Map<String, FetchResult>> savedPerUrlCache;
    private Path savedSubmissionsDir;
    private int savedMaxEntryChars;
    private long savedMaxFileBytes;
    private Set<String> savedProtectedHosts;
    private long savedNextFetchSlot;
    private CloseableHttpClient savedFetchClient;

    @BeforeEach
    void isolateStaticState() throws Exception {
        savedStateMap = new EnumMap<>(stateMap());
        savedPerUrlCache = new EnumMap<>(perUrlCache());
        savedSubmissionsDir = staticField("submissionsDir", Path.class);
        savedMaxEntryChars = staticField("maxSubmissionEntryChars", Integer.class);
        savedMaxFileBytes = staticField("maxSubmissionFileBytes", Long.class);
        savedProtectedHosts = staticField("protectedHosts", Set.class);
        savedNextFetchSlot = nextFetchSlot().get();
        savedFetchClient = staticField("FETCH_CLIENT", CloseableHttpClient.class);

        stateMap().clear();
        perUrlCache().clear();
        setStaticField("submissionsDir", temporaryDirectory);
        setStaticField("maxSubmissionEntryChars", 128);
        setStaticField("maxSubmissionFileBytes", 16_384L);
        setStaticField("protectedHosts", Set.of());
    }

    @AfterEach
    void restoreStaticState() throws Exception {
        stateMap().clear();
        stateMap().putAll(savedStateMap);
        perUrlCache().clear();
        perUrlCache().putAll(savedPerUrlCache);
        setStaticField("submissionsDir", savedSubmissionsDir);
        setStaticField("maxSubmissionEntryChars", savedMaxEntryChars);
        setStaticField("maxSubmissionFileBytes", savedMaxFileBytes);
        setStaticField("protectedHosts", savedProtectedHosts);
        nextFetchSlot().set(savedNextFetchSlot);
        setStaticFinalField("FETCH_CLIENT", savedFetchClient);
        Thread.interrupted();
    }

    @Test
    void endpointLookupAndLookupFailureStatesAreExplicit() {
        assertThat(LocalListUtil.findByEndpointName("openphish")).isEqualTo(Descriptor.OPEN_PHISH);
        assertThat(LocalListUtil.findByEndpointName("missing")).isNull();
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://example.com"))
                .isEqualTo(LookupResult.FAILED);

        stateMap().put(Descriptor.OPEN_PHISH, new AtomicReference<>(ListSnapshot.EMPTY));
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://example.com"))
                .isEqualTo(LookupResult.FAILED);
    }

    @Test
    void lookupHandlesInvalidUrisHostsDomainsPathsAndRetainedQueries() {
        putSnapshot(Descriptor.OPEN_PHISH, Set.of(
                "blocked.example.com",
                "malware.example.co.uk",
                "host.test/parent",
                "drive.google.com/uc?export=download&id=42"
        ));

        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "not a uri")).isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "mailto:user@example.com"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://www.blocked.example.com/"))
                .isEqualTo(LookupResult.PHISHING);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://a.malware.example.co.uk"))
                .isEqualTo(LookupResult.PHISHING);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://host.test/parent/child///"))
                .isEqualTo(LookupResult.PHISHING);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH,
                "https://drive.google.com/uc?id=42&export=download&discarded=yes"))
                .isEqualTo(LookupResult.PHISHING);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://drive.google.com/uc?id=wrong"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://unblocked.example.com/path"))
                .isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void lookupDoesNotTreatPublicSuffixesAsAncestors() {
        putSnapshot(Descriptor.URLHAUS, Set.of("com", "co.uk"));

        assertThat(LocalListUtil.lookup(Descriptor.URLHAUS, "https://safe.example.com"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.URLHAUS, "https://safe.example.co.uk"))
                .isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void submitRejectsWrongOrUninitializedDescriptors() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> LocalListUtil.submit(Descriptor.OPEN_PHISH, List.of("bad.example"), "abc"))
                .withMessage("Not a submission feed: openphish");
        assertThatIllegalStateException()
                .isThrownBy(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("bad.example"), "abc"))
                .withMessage("No state slot exists for descriptor");
    }

    @Test
    void submitNormalizesPersistsDeduplicatesAndRejectsUnsafeEntries() throws IOException {
        putSnapshot(Descriptor.ACOMICS, null);
        setStaticField("protectedHosts", Set.of("protected.com"));

        try (MockedStatic<NetworkUtil> network = mockStatic(NetworkUtil.class)) {
            network.when(() -> NetworkUtil.isPrivateHost(anyString()))
                    .thenReturn(false);

            Map<String, Integer> counts = LocalListUtil.submit(Descriptor.ACOMICS, Arrays.asList(
                    "https://evil.com/path",
                    "https://evil.com/path",
                    "protected.com",
                    "localhost.local",
                    null,
                    "bad entry"
            ), "a:b-c 12");

            assertThat(counts).containsEntry("accepted", 1).containsEntry("duplicates", 1).containsEntry("rejected", 4);
            assertThat(snapshot(Descriptor.ACOMICS)).containsExactly("evil.com/path");
            String persisted = Files.readString(temporaryDirectory.resolve("acomics.txt"));
            assertThat(persisted).contains("source=abc12").contains("evil.com/path\n");

            Map<String, Integer> replay = LocalListUtil.submit(
                    Descriptor.ACOMICS, List.of("https://evil.com/path"), "ignored");
            assertThat(replay).containsEntry("accepted", 0).containsEntry("duplicates", 1).containsEntry("rejected", 0);
        }
    }

    @Test
    void submitEnforcesEntryAndFileCapsAndRepairsHandEditedLineBoundary() throws IOException {
        putSnapshot(Descriptor.ACOMICS, Set.of());
        setStaticField("maxSubmissionEntryChars", 8);
        assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("verylong.example.com"), "a"))
                .containsEntry("rejected", 1);

        setStaticField("maxSubmissionEntryChars", 128);
        setStaticField("maxSubmissionFileBytes", 1L);
        assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("evil.com"), "a"))
                .containsEntry("rejected", 1);

        setStaticField("maxSubmissionFileBytes", 16_384L);
        Path file = temporaryDirectory.resolve("acomics.txt");
        Files.writeString(file, "existing.com", StandardCharsets.UTF_8);
        assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("evil.com"), "a"))
                .containsEntry("accepted", 1);
        assertThat(Files.readString(file)).startsWith("existing.com\n# ").contains("evil.com\n");

        putSnapshot(Descriptor.ACOMICS, fullDomainSet());
        assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("new.example"), "a"))
                .containsEntry("rejected", 1);
    }

    @Test
    void persistedSubmissionLoaderHandlesMissingTruncatedAndProtectedEntries() throws Exception {
        putSnapshot(Descriptor.ACOMICS, null);
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);
        assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();

        setStaticField("protectedHosts", Set.of("protected.com"));
        Files.writeString(temporaryDirectory.resolve("acomics.txt"),
                "good.example.com\nprotected.com\nunfinished.example.com", StandardCharsets.UTF_8);
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);

        assertThat(snapshot(Descriptor.ACOMICS)).containsExactly("good.example.com");
    }

    @Test
    void persistedSubmissionLoaderRefusesAnOversizedFileWithoutReadingIt() throws Exception {
        putSnapshot(Descriptor.ACOMICS, null);
        Path file = temporaryDirectory.resolve("acomics.txt");

        try (var channel = Files.newByteChannel(file, java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(16L * 1024L * 1024L);
            channel.write(ByteBuffer.wrap(new byte[]{'\n'}));
        }

        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);
        assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();
    }

    @Test
    void plainTextAndCsvParsersNormalizeSupportedFeedSyntax() {
        Set<String> text = (Set<String>) invoke("parsePlainText", new Class<?>[]{InputStream.class},
                stream("# comment\n\n0.0.0.0 Example.COM # note\n127.0.0.1 ignored.com extra\n"
                        + "https://www.Path.Test/One/?ignored=yes\nnot a host\n"));
        assertThat(text).containsExactlyInAnyOrder("example.com", "ignored.com", "path.test/one");

        Set<String> csv = (Set<String>) invoke("parseCsv", new Class<?>[]{InputStream.class},
                stream("# header\n\none,two,three,HTTP://WWW.EVIL.COM/a/,tag\nshort,line\n,,,,\n"));
        assertThat(csv).containsExactly("evil.com/a");
    }

    @Test
    void jsonParserHandlesStringsObjectsNullsAndNestedValues() {
        Set<String> strings = (Set<String>) invoke("parseJson", new Class<?>[]{InputStream.class, String.class},
                stream("[null,\"WWW.Example.COM\",\"https://path.test/a/\"]"), null);
        assertThat(strings).containsExactlyInAnyOrder("example.com", "path.test/a");

        Set<String> objects = (Set<String>) invoke("parseJson", new Class<?>[]{InputStream.class, String.class},
                stream("[{\"ignored\":{\"nested\":[1]},\"Url\":\"https:\\/\\/www.evil.com\\/x\\/\"},"
                        + "{\"Url\":null},{\"Other\":\"missing\"}]"), "Url");
        assertThat(objects).containsExactly("evil.com/x");

        Set<String> nestedArray = (Set<String>) invoke("parseJson", new Class<?>[]{InputStream.class, String.class},
                stream("[{\"ignored\":[1],\"Url\":\"array.example\"}]"), "Url");
        assertThat(nestedArray).containsExactly("array.example");
    }

    @Test
    void parsersRejectMalformedJsonAndOversizedLines() throws IOException {
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("parseJson", new Class<?>[]{InputStream.class, String.class}, stream("{}"), null));
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("parseJson", new Class<?>[]{InputStream.class, String.class}, stream("[1]"), null));
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("parseJson", new Class<?>[]{InputStream.class, String.class}, stream("[\"x\"]"), "Url"));
        String oversized = "a".repeat(10_249) + "\n";
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("parsePlainText", new Class<?>[]{InputStream.class}, stream(oversized)));
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("parseCsv", new Class<?>[]{InputStream.class}, stream(oversized)));

        JsonParser endedObject = mock(JsonParser.class);
        when(endedObject.nextToken()).thenReturn(null);
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("extractObjectField", new Class<?>[]{JsonParser.class, String.class},
                        endedObject, "Url"));

        JsonParser invalidObject = mock(JsonParser.class);
        when(invalidObject.nextToken()).thenReturn(JsonToken.VALUE_STRING);
        assertReflectionCause(IllegalArgumentException.class,
                () -> invoke("extractObjectField", new Class<?>[]{JsonParser.class, String.class},
                        invalidObject, "Url"));
    }

    @Test
    void normalizationCoversUrlsHostsCommentsAndHostsFileAddresses() {
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, " HTTPS://WWW.Example.COM/a/// "))
                .isEqualTo("example.com/a");
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, " / ")).isNull();
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, "host\\path")).isNull();
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "# comment")).isNull();
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "  .WWW.Example.COM.  # note"))
                .isEqualTo("example.com");
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "127.0.0.1 host.test trailing"))
                .isEqualTo("host.test");
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "127.00.0.1 host.test"))
                .isEqualTo("127.00.0.1");
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "http:///missing-host")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "com")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "a".repeat(254) + ".com")).isNull();
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https://www.example.com/"))
                .isEqualTo("example.com");
    }

    @Test
    void hostAddressAndMatchingHelpersCoverParentAndInvalidPaths() {
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "localhost")).isEqualTo(true);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "fe80::1")).isEqualTo(true);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "255.255.255.255")).isEqualTo(true);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "256.0.0.1")).isEqualTo(false);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "01.0.0.1")).isEqualTo(false);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "one.two")).isEqualTo(false);
        assertThat(invoke("isHostInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("example.co.uk"), "a.example.co.uk")).isEqualTo(true);
        assertThat(invoke("isHostInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("co.uk"), "a.example.co.uk")).isEqualTo(false);
        assertThat(invoke("isUrlInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("example.com/a"), "https://www.example.com/a/b/")).isEqualTo(true);
        assertThat(invoke("isUrlInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("example.com/a"), "example.com\\a")).isEqualTo(false);
    }

    @Test
    void submissionValidationRejectsMalformedPrivateAndProtectedCandidates() throws Exception {
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "example.com/a?x=1", 11))
                .isEqualTo(true);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "-bad.com", -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "bad-.com", -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "bad_.com", -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "good.com/bad space", 8))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "", -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class},
                "a".repeat(64) + ".example", -1)).isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "bad$.example", -1))
                .isEqualTo(false);
        assertThat(invoke("isAcceptableSubmission", new Class<?>[]{String.class}, "example.com")).isEqualTo(true);
        assertThat(invoke("isAcceptableSubmission", new Class<?>[]{String.class}, "127.0.0.1")).isEqualTo(false);

        setStaticField("protectedHosts", Set.of("example.com"));
        assertThat(invoke("isAcceptableSubmission", new Class<?>[]{String.class}, "sub.example.com/a"))
                .isEqualTo(false);
    }

    @Test
    void cappedStreamCountsSingleAndBulkReadsAndRejectsOversizeInput() throws Exception {
        InputStream capped = (InputStream) invoke("cappedInputStream", new Class<?>[]{InputStream.class}, stream("abc"));
        assertThat(capped.read()).isEqualTo('a');
        byte[] remainder = new byte[4];
        assertThat(capped.read(remainder, 1, 3)).isEqualTo(2);
        assertThat(capped.read(remainder, 0, remainder.length)).isEqualTo(-1);
        assertThat(capped.read()).isEqualTo(-1);

        InputStream tooLarge = (InputStream) invoke("cappedInputStream", new Class<?>[]{InputStream.class},
                new ByteArrayInputStream(new byte[16 * 1024 * 1024 + 1]));
        assertThatThrownBy(() -> {
            byte[] buffer = new byte[8192];
            while (tooLarge.read(buffer) != -1) {
                // Consume until the cap trips.
            }
        }).isInstanceOf(IOException.class).hasMessageContaining("List exceeds");
    }

    @Test
    void publicationAndThrottlingHandleEmptyStateMissingStateAndInterruption() throws Exception {
        putSnapshot(Descriptor.OPEN_PHISH, Set.of("existing.com"));
        invoke("applyContent", new Class<?>[]{Descriptor.class, Set.class}, Descriptor.OPEN_PHISH, Set.of());
        assertThat(snapshot(Descriptor.OPEN_PHISH)).containsExactly("existing.com");

        invoke("applyContent", new Class<?>[]{Descriptor.class, Set.class},
                Descriptor.OPEN_PHISH, Set.of("new.example.com"));
        assertThat(snapshot(Descriptor.OPEN_PHISH)).containsExactly("new.example.com");
        stateMap().clear();
        invoke("applyContent", new Class<?>[]{Descriptor.class, Set.class},
                Descriptor.OPEN_PHISH, Set.of("ignored.example.com"));

        nextFetchSlot().set(0L);
        invoke("throttleFetches", new Class<?>[0]);
        nextFetchSlot().set(System.currentTimeMillis());
        Thread.currentThread().interrupt();
        try {
            invoke("throttleFetches", new Class<?>[0]);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void responseHeaderHelpersHandleAllRetryHintForms() {
        ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        assertThat(invoke("isRateLimited", new Class<?>[]{ClassicHttpResponse.class}, response)).isEqualTo(false);
        Header retry = mock(Header.class);
        when(retry.getValue()).thenReturn(" 2 ");
        when(response.getFirstHeader("Retry-After")).thenReturn(retry);
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class}, response, false))
                .isEqualTo(2_000L);

        Header negative = mock(Header.class);
        when(negative.getValue()).thenReturn("-1");
        Header reset = mock(Header.class);
        when(reset.getValue()).thenReturn("not-a-number");
        when(response.getFirstHeader("Retry-After")).thenReturn(negative);
        when(response.getFirstHeader("X-RateLimit-Reset")).thenReturn(reset);
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class}, response, false))
                .isEqualTo(0L);
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class}, response, true))
                .isEqualTo(0L);

        Header futureReset = mock(Header.class);
        when(futureReset.getValue()).thenReturn(Long.toString(System.currentTimeMillis() / 1_000L + 60L));
        when(response.getFirstHeader("X-RateLimit-Reset")).thenReturn(futureReset);
        assertThat((Long) invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class},
                response, true)).isPositive();
        when(futureReset.getValue()).thenReturn(Long.toString(System.currentTimeMillis() / 1_000L - 60L));
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class}, response, true))
                .isEqualTo(0L);

        Header remaining = mock(Header.class);
        when(remaining.getValue()).thenReturn("0");
        when(response.getFirstHeader("X-RateLimit-Remaining")).thenReturn(remaining);
        assertThat(invoke("isRateLimited", new Class<?>[]{ClassicHttpResponse.class}, response)).isEqualTo(true);
        when(remaining.getValue()).thenReturn("1");
        assertThat(invoke("isRateLimited", new Class<?>[]{ClassicHttpResponse.class}, response)).isEqualTo(false);
    }

    @Test
    void constructorClampsLimitsAndNormalizesProtectedHosts() {
        new LocalListUtil(" ", 0, Long.MAX_VALUE, " .WWW.Protected.com., com, host.test ");

        assertThat(staticField("submissionsDir", Path.class)).isEqualTo(temporaryDirectory);
        assertThat(staticField("maxSubmissionEntryChars", Integer.class)).isEqualTo(1);
        assertThat(staticField("maxSubmissionFileBytes", Long.class)).isEqualTo(16L * 1024L * 1024L);
        assertThat(staticField("protectedHosts", Set.class)).containsExactlyInAnyOrder("protected.com", "host.test");

        new LocalListUtil(temporaryDirectory.resolve("configured").toString(), 20_000, 0L, "");

        assertThat(staticField("submissionsDir", Path.class)).isEqualTo(temporaryDirectory.resolve("configured"));
        assertThat(staticField("maxSubmissionEntryChars", Integer.class)).isEqualTo(10_248);
        assertThat(staticField("maxSubmissionFileBytes", Long.class)).isEqualTo(1L);
    }

    @Test
    void initCreatesAllStateSlotsAndLoadsSubmissionFeeds() throws Exception {
        setStaticFinalField("FETCH_CLIENT", mock(CloseableHttpClient.class));
        LocalListUtil util = new LocalListUtil(temporaryDirectory.toString(), 128, 16_384L, "");

        // The real scheduler would run the refresh task on a background thread at an unpredictable
        // moment, so swap in one that hands the task back for the test to run deterministically.
        List<Runnable> scheduled = new ArrayList<>();
        ScheduledExecutorService capturing = mock(ScheduledExecutorService.class);
        when(capturing.scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any(TimeUnit.class)))
                .thenAnswer(invocation -> {
                    scheduled.add(invocation.getArgument(0));
                    return null;
                });

        ScheduledExecutorService original = instanceField(util, "scheduler");
        setInstanceField(util, "scheduler", capturing);

        try {
            // The real scheduler's thread factory only runs once its worker thread is started.
            AtomicReference<Thread> worker = new AtomicReference<>();
            original.submit(() -> worker.set(Thread.currentThread())).get(10L, TimeUnit.SECONDS);
            assertThat(worker.get().getName()).isEqualTo("local-list-refresh");
            assertThat(worker.get().isDaemon()).isTrue();

            util.init();

            assertThat(stateMap()).hasSize(Descriptor.values().length);
            assertThat(perUrlCache()).hasSize(Descriptor.values().length);
            assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();
            assertThat(scheduled).isNotEmpty();

            // Dropping the cache slots makes the scheduled refresh bail out immediately instead of
            // reaching the network, so the scheduled task body itself stays cheap and deterministic.
            perUrlCache().clear();
            scheduled.getFirst().run();
            assertThat(perUrlCache()).isEmpty();
        } finally {
            original.shutdownNow();
            util.destroy();
        }
    }

    @Test
    void fetchAttemptsSetRequestHeadersAndParseSuccessfulResponses() {
        List<ClassicHttpResponse> responses = List.of(
                response(200, "text/plain", "https://www.example.com/path/\n", "etag-1", "modified-1"),
                response(200, "application/vnd.github.raw", "github.example\n", null, null),
                response(201, "application/json", "[{\"Url\":\"https://json.example/a\"}]", null, null)
        );
        List<org.apache.hc.core5.http.ClassicHttpRequest> requests = new ArrayList<>();
        setStaticFinalField("FETCH_CLIENT", responseClient(requests, responses));

        FetchResult plain = fetchAttempt(Descriptor.PHISHUNT_IO, "https://feed.test/plain", "old-etag", "old-date");
        FetchResult github = fetchAttempt(Descriptor.VALIDIN, "https://feed.test/github", null, "old-date");
        FetchResult json = fetchAttempt(Descriptor.AA419, "https://feed.test/json", null, null);

        assertThat(plain.domainSet()).containsExactly("example.com/path");
        assertThat(plain.etag()).isEqualTo("etag-1");
        assertThat(plain.lastModified()).isEqualTo("modified-1");
        assertThat(github.domainSet()).containsExactly("github.example");
        assertThat(json.domainSet()).containsExactly("json.example/a");
        assertThat(requests.get(0).getFirstHeader("Accept").getValue()).contains("application/json");
        assertThat(requests.get(0).getFirstHeader("If-None-Match").getValue()).isEqualTo("old-etag");
        assertThat(requests.get(0).getFirstHeader("If-Modified-Since")).isNull();
        assertThat(requests.get(1).getFirstHeader("Accept").getValue()).isEqualTo("application/vnd.github.raw");
        assertThat(requests.get(1).getFirstHeader("X-GitHub-Api-Version").getValue()).isEqualTo("2022-11-28");
        assertThat(requests.get(1).getFirstHeader("User-Agent").getValue()).isEqualTo("OspreyProxy");
        assertThat(requests.get(1).getFirstHeader("If-Modified-Since").getValue()).isEqualTo("old-date");
    }

    @Test
    void fetchAttemptRejectsUnusableResponsesAndSignalsRetryableStatuses() {
        assertThat(fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/not-modified", null, null,
                response(304, null, null, null, null))).isNull();

        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/not-found", null, null,
                response(404, null, null, null, null)));
        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/bad-type", null, null,
                response(200, "image/png", "example.com\n", null, null)));
        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/no-body", null, null,
                response(200, "text/plain", null, null, null)));
        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/bad-body", null, null,
                response(200, "application/json", "@", null, null)));
        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/empty", null, null,
                response(200, "text/plain", "\n# only comments\n", null, null)));
        assertThatThrownBy(() -> fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/retry", null, null,
                response(429, null, null, null, null)))
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(RuntimeException.class)
                .hasMessageContaining("HTTP 429");
        assertThatThrownBy(() -> fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/rate-limit", null, null,
                response(403, null, null, null, null, "X-RateLimit-Remaining", "0")))
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(RuntimeException.class)
                .hasMessageContaining("HTTP 403");
        assertThatThrownBy(() -> fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/unavailable", null, null,
                response(503, null, null, null, null)))
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(RuntimeException.class)
                .hasMessageContaining("HTTP 503");
        assertReflectionCause(IllegalStateException.class, () -> fetchAttempt(
                Descriptor.OPEN_PHISH, "https://feed.test/forbidden", null, null,
                response(403, null, null, null, null, "X-RateLimit-Remaining", "1")));
        assertThatThrownBy(() -> fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/bad-gateway", null, null,
                response(502, null, null, null, null)))
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(RuntimeException.class)
                .hasMessageContaining("HTTP 502");
        assertThatThrownBy(() -> fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/gateway-timeout", null, null,
                response(504, null, null, null, null)))
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(RuntimeException.class)
                .hasMessageContaining("HTTP 504");
    }

    @Test
    void fetchRawAndRefreshPreserveCachedListsAndPublishChangedContent() {
        assertReflectionCause(IllegalStateException.class, () -> fetchRaw(
                Descriptor.OPEN_PHISH, "https://feed.test/slow", response(429, null, null, null, null,
                        "Retry-After", "11")));

        invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.OPEN_PHISH);

        putSnapshot(Descriptor.OPEN_PHISH, Set.of("old.example"));
        perUrlCache().put(Descriptor.OPEN_PHISH, new HashMap<>());
        String url = Descriptor.OPEN_PHISH.getResolvedUrls().getFirst();
        perUrlCache().get(Descriptor.OPEN_PHISH).put(url, new FetchResult(Set.of("old.example"), "previous", null));
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(),
                List.of(response(200, "text/plain", "new.example\n", "new-etag", null))));

        invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.OPEN_PHISH);

        assertThat(snapshot(Descriptor.OPEN_PHISH)).containsExactly("new.example");
        assertThat(perUrlCache().get(Descriptor.OPEN_PHISH).get(url).etag()).isEqualTo("new-etag");
    }

    @Test
    void fetchAndUpdateKeepsCachedContentWhenTheSourceIsNotModified() {
        String url = Descriptor.OPEN_PHISH.getResolvedUrls().getFirst();
        putSnapshot(Descriptor.OPEN_PHISH, Set.of("old.example"));
        Map<String, FetchResult> cache = new HashMap<>();
        cache.put(url, new FetchResult(Set.of("old.example"), "previous", null));
        perUrlCache().put(Descriptor.OPEN_PHISH, cache);
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(),
                List.of(response(304, null, null, null, null))));
        nextFetchSlot().set(0L);

        invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.OPEN_PHISH);

        assertThat(snapshot(Descriptor.OPEN_PHISH)).containsExactly("old.example");
        assertThat(cache.get(url).etag()).isEqualTo("previous");
    }

    @Test
    void normalizationAndCollectionLimitsCoverRejectedEdgeCases() {
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, "")).isNull();
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, "http://Example.COM/a/"))
                .isEqualTo("example.com/a");
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, "http://")).isNull();
        assertThat(invoke("normalizeUrlForLookup", new Class<?>[]{String.class}, "example.com space")).isNull();
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "value.example # comment"))
                .isEqualTo("value.example");
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "value.example#"))
                .isEqualTo("value.example");
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "#")).isNull();
        assertThat(invoke("normalizeListEntry", new Class<?>[]{String.class}, "localhost host.test"))
                .isEqualTo("host.test");
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https:///missing")).isNull();
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https://example.com/"))
                .isEqualTo("example.com");
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "...")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "example.com/path")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "bad_domain.com")).isEqualTo("bad_domain.com");
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, ".0.0.1")).isEqualTo(false);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "1000.0.0.1")).isEqualTo(false);
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "1.a.0.1")).isEqualTo(false);
        assertThat(invoke("isUrlInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("example.com/a"), "example.com/a")).isEqualTo(true);

        Collection<String> fullSet = fullDomainSet();
        assertReflectionCause(IllegalStateException.class, () -> invoke(
                "addNormalizedEntry", new Class<?>[]{String.class, Collection.class}, "example.com", fullSet));
    }

    @Test
    void submissionProcessingCoversEmptyFilesAndValidationBoundaries() throws Exception {
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);

        putSnapshot(Descriptor.ACOMICS, null);
        Path file = temporaryDirectory.resolve("acomics.txt");
        Files.writeString(file, "");
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);
        assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();

        Files.writeString(file, "truncated.example.com");
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);
        assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();

        Files.writeString(file, "good.example.com\n");
        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);
        assertThat(snapshot(Descriptor.ACOMICS)).containsExactly("good.example.com");

        assertThat(invoke("isAcceptableSubmission", new Class<?>[]{String.class}, "bad_.example")).isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "a".repeat(254), -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "good..example", -1))
                .isEqualTo(false);
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class}, "bad{.example", -1))
                .isEqualTo(false);
        String validPath = "a1-b.example/a1%~";
        assertThat(invoke("isWellFormedSubmission", new Class<?>[]{String.class, int.class},
                validPath, validPath.indexOf('/'))).isEqualTo(true);
        assertThat(invoke("isHostInSet", new Class<?>[]{Collection.class, String.class},
                Set.of(), "localhost")).isEqualTo(false);

        try (MockedStatic<NetworkUtil> network = mockStatic(NetworkUtil.class)) {
            network.when(() -> NetworkUtil.isPrivateHost(anyString()))
                    .thenReturn(false);
            putSnapshot(Descriptor.ACOMICS, Set.of());
            Files.writeString(file, "");
            assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("first.example.com"), "source"))
                    .containsEntry("accepted", 1);
            assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("second.example.com"), "source"))
                    .containsEntry("accepted", 1);
            putSnapshot(Descriptor.ACOMICS, fullDomainSet());
            assertThat(LocalListUtil.submit(Descriptor.ACOMICS, List.of("limit.example.com"), "source"))
                    .containsEntry("rejected", 1);
        }
    }

    @Test
    void normalizationCoversEmptyPathsAndCharacterBoundaries() {
        putSnapshot(Descriptor.OPEN_PHISH, Set.of());
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://unblocked.example.com"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://unblocked.example.com/"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(LocalListUtil.lookup(Descriptor.OPEN_PHISH, "https://unblocked.example.com////"))
                .isEqualTo(LookupResult.ALLOWED);
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https://example.org"))
                .isEqualTo("example.org");
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https://example.org////"))
                .isEqualTo("example.org");
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "example .org")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "example.\\org")).isNull();
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "valid.example"))
                .isEqualTo("valid.example");
        assertThat(invoke("normalizeHostnameEntry", new Class<?>[]{String.class}, "co.uk")).isNull();
        assertThat(invoke("looksLikeHostsFileAddress", new Class<?>[]{String.class}, "1./.0.1"))
                .isEqualTo(false);

        Set<String> destination = new HashSet<>(Set.of("existing.example"));
        invoke("addNormalizedEntry", new Class<?>[]{String.class, Collection.class}, "existing.example", destination);
        assertThat(destination).containsExactly("existing.example");
    }

    @Test
    void fetchAndUpdateCoversEveryAccumulateState() {
        Map<String, String> environment = mutableEnvironment();
        Map<String, String> caseInsensitiveEnvironment = caseInsensitiveEnvironment();
        String originalKey = environment.put("AA419_API_KEY", "test-key");
        String originalCaseInsensitiveKey = caseInsensitiveEnvironment.put("AA419_API_KEY", "test-key");

        try {
            perUrlCache().put(Descriptor.AA419, new HashMap<>());
            setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(), List.of(
                    response(200, "application/json", "[{\"Url\":\"first.example\"}]", null, null),
                    response(200, "application/json", "[{\"Url\":\"second.example\"}]", null, null),
                    response(200, "application/json", "[{\"Url\":\"stable.example\"}]", null, null)
            )));

            nextFetchSlot().set(0L);
            invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.AA419);

            putSnapshot(Descriptor.AA419, null);
            nextFetchSlot().set(0L);
            invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.AA419);
            assertThat(snapshot(Descriptor.AA419)).containsExactly("second.example");

            putSnapshot(Descriptor.AA419, Set.of("stable.example"));
            nextFetchSlot().set(0L);
            invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.AA419);
            assertThat(snapshot(Descriptor.AA419)).containsExactly("stable.example");
        } finally {
            restoreEnvironmentValue(environment, "AA419_API_KEY", originalKey);
            restoreEnvironmentValue(caseInsensitiveEnvironment, "AA419_API_KEY", originalCaseInsensitiveKey);
        }
    }

    @Test
    void fetchAndUpdateKeepsTheCurrentSnapshotWhenTheMergedLimitIsExceeded() {
        Map<String, String> environment = mutableEnvironment();
        Map<String, String> caseInsensitiveEnvironment = caseInsensitiveEnvironment();
        String originalKey = environment.put("AA419_API_KEY", "test-key");
        String originalCaseInsensitiveKey = caseInsensitiveEnvironment.put("AA419_API_KEY", "test-key");

        try {
            putSnapshot(Descriptor.AA419, Set.of("stable.example"));
            Map<String, FetchResult> cache = new HashMap<>();
            cache.put("preserved-large-source", new FetchResult(overLimitDomainSet(), null, null));
            perUrlCache().put(Descriptor.AA419, cache);
            setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(),
                    List.of(response(200, "application/json", "[{\"Url\":\"fresh.example\"}]", null, null))));

            nextFetchSlot().set(0L);
            invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.AA419);

            assertThat(snapshot(Descriptor.AA419)).containsExactly("stable.example");
            cache.clear();
        } finally {
            restoreEnvironmentValue(environment, "AA419_API_KEY", originalKey);
            restoreEnvironmentValue(caseInsensitiveEnvironment, "AA419_API_KEY", originalCaseInsensitiveKey);
        }
    }

    @Test
    void fetchRawUsesBackoffBeforeGivingUpAfterTheFinalRetry() {
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(), List.of(
                response(429, null, null, null, null),
                response(429, null, null, null, null),
                response(429, null, null, null, null)
        )));
        nextFetchSlot().set(0L);
        Thread.currentThread().interrupt();

        try {
            assertReflectionCause(IllegalStateException.class, () -> invoke(
                    "fetchRaw", new Class<?>[]{Descriptor.class, String.class, String.class, String.class},
                    Descriptor.OPEN_PHISH, "https://feed.test/retry", null, null));
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void fetchUsesGithubAuthenticationAndCsvParsingWhenConfigured() throws Exception {
        String githubToken = "GITHUB_API_TOKEN";
        String aa419Key = "AA419_API_KEY";
        Map<String, String> environment = mutableEnvironment();
        Map<String, String> caseInsensitiveEnvironment = caseInsensitiveEnvironment();
        String originalGithubToken = environment.remove(githubToken);
        String originalCaseInsensitiveGithubToken = caseInsensitiveEnvironment.remove(githubToken);
        String originalAa419Key = environment.put(aa419Key, "auth-key");
        String originalCaseInsensitiveAa419Key = caseInsensitiveEnvironment.put(aa419Key, "auth-key");
        Format originalFormat = descriptorField(Descriptor.PHISHUNT_IO, "format");

        try {
            List<org.apache.hc.core5.http.ClassicHttpRequest> requests = new ArrayList<>();
            setStaticFinalField("FETCH_CLIENT", responseClient(requests, List.of(
                    response(200, "text/plain", "missing-token.example\n", null, null),
                    response(200, "text/plain", "blank-token.example\n", null, null),
                    response(200, "text/plain", "token.example\n", null, null),
                    response(200, "application/json", "[{\"Url\":\"authenticated.example\"}]", null, null),
                    response(200, "text/plain", "one,two,three,https://csv.example/path,tag\n", null, null)
            )));

            fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/no-token", null, null);

            environment.put(githubToken, " ");
            caseInsensitiveEnvironment.put(githubToken, " ");
            fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/blank-token", null, null);

            environment.put(githubToken, "token");
            caseInsensitiveEnvironment.put(githubToken, "token");
            fetchAttempt(Descriptor.OPEN_PHISH, "https://feed.test/token", null, null);
            FetchResult authenticated = fetchAttempt(Descriptor.AA419, "https://feed.test/authenticated", null, null);

            setDescriptorField(Descriptor.PHISHUNT_IO, "format", Format.CSV);
            FetchResult csv = fetchAttempt(Descriptor.PHISHUNT_IO, "https://feed.test/csv", null, null);

            assertThat(requests.get(0).getFirstHeader("Authorization")).isNull();
            assertThat(requests.get(1).getFirstHeader("Authorization")).isNull();
            assertThat(requests.get(2).getFirstHeader("Authorization").getValue()).isEqualTo("Bearer token");
            assertThat(requests.get(3).getFirstHeader("Auth-API-Id").getValue()).isEqualTo("auth-key");
            assertThat(authenticated.domainSet()).containsExactly("authenticated.example");
            assertThat(csv.domainSet()).containsExactly("csv.example/path");
        } finally {
            setDescriptorField(Descriptor.PHISHUNT_IO, "format", originalFormat);
            restoreEnvironmentValue(environment, githubToken, originalGithubToken);
            restoreEnvironmentValue(caseInsensitiveEnvironment, githubToken, originalCaseInsensitiveGithubToken);
            restoreEnvironmentValue(environment, aa419Key, originalAa419Key);
            restoreEnvironmentValue(caseInsensitiveEnvironment, aa419Key, originalCaseInsensitiveAa419Key);
        }
    }

    @Test
    void destroyLogsAFailureClosingTheSharedHttpClient() throws Exception {
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        doThrow(new IOException("already closed")).when(client).close();
        setStaticFinalField("FETCH_CLIENT", client);

        new LocalListUtil(" ", 0, 0L, " ").destroy();

        verify(client).close();
    }

    @Test
    void persistedSubmissionLoaderSurvivesAFileThePlainTextParserRejects() throws Exception {
        putSnapshot(Descriptor.ACOMICS, null);
        Files.writeString(temporaryDirectory.resolve("acomics.txt"), "a".repeat(10_249) + '\n',
                StandardCharsets.UTF_8);

        invoke("loadSubmissionFeed", new Class<?>[]{Descriptor.class}, Descriptor.ACOMICS);

        // The parse failure is contained; the feed is published empty rather than left uninitialized.
        assertThat(snapshot(Descriptor.ACOMICS)).isEmpty();
    }

    @Test
    void isHostInSetFallsBackToTwoLabelsWhenGuavaRejectsTheHost() {
        // "a..example.com" has an empty label, so InternetDomainName.from refuses it and the
        // ancestor walk falls back to the default two-label registrable domain.
        assertThat(invoke("isHostInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("example.com"), "a..example.com")).isEqualTo(true);
        assertThat(invoke("isHostInSet", new Class<?>[]{Collection.class, String.class},
                Set.of("other.example"), "a..example.com")).isEqualTo(false);
    }

    @Test
    void fetchAndUpdateKeepsThePreviousSnapshotWhenASourceFetchFails() {
        putSnapshot(Descriptor.OPEN_PHISH, Set.of("old.example"));
        perUrlCache().put(Descriptor.OPEN_PHISH, new HashMap<>());
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(),
                List.of(response(404, null, null, null, null))));
        nextFetchSlot().set(0L);

        invoke("fetchAndUpdate", new Class<?>[]{Descriptor.class}, Descriptor.OPEN_PHISH);

        assertThat(snapshot(Descriptor.OPEN_PHISH)).containsExactly("old.example");
        assertThat(perUrlCache().get(Descriptor.OPEN_PHISH)).isEmpty();
    }

    @Test
    void attemptFetchReportsParseFailuresAsIoFailures() {
        assertReflectionCause(IOException.class, () -> fetchAttempt(Descriptor.OPEN_PHISH,
                "https://feed.test/oversized", null, null,
                response(200, "text/plain", "a".repeat(10_249) + '\n', null, null)));
    }

    @Test
    void retryAfterMillisIgnoresHttpDateHints() {
        Header httpDate = header("Wed, 21 Oct 2026 07:28:00 GMT");
        ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        when(response.getFirstHeader("Retry-After")).thenReturn(httpDate);

        // The HTTP-date form is not parsed, and with no reset header there is no hint at all.
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class},
                response, false)).isEqualTo(0L);
        assertThat(invoke("retryAfterMillis", new Class<?>[]{ClassicHttpResponse.class, boolean.class},
                response, true)).isEqualTo(0L);
    }

    @Test
    void sleepMillisSleepsAndRestoresTheInterruptFlagWhenInterrupted() {
        invoke("sleepMillis", new Class<?>[]{long.class}, 1L);
        assertThat(Thread.currentThread().isInterrupted()).isFalse();

        Thread.currentThread().interrupt();

        try {
            invoke("sleepMillis", new Class<?>[]{long.class}, 60_000L);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void normalizeUrlEntryRejectsEntriesThatUriCannotParse() {
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "http://exa mple.com/path")).isNull();
        assertThat(invoke("normalizeUrlEntry", new Class<?>[]{String.class}, "https://example.com/path"))
                .isEqualTo("example.com/path");
    }

    private static Set<String> fullDomainSet() {
        return new AbstractSet<>() {
            @Override
            public Iterator<String> iterator() {
                return Collections.emptyIterator();
            }

            @Override
            public int size() {
                return 1_000_000;
            }
        };
    }

    private static Set<String> overLimitDomainSet() {
        return new AbstractSet<>() {
            @Override
            public Iterator<String> iterator() {
                return new Iterator<>() {
                    private int current;

                    @Override
                    public boolean hasNext() {
                        return current <= 1_000_000;
                    }

                    @Override
                    public String next() {
                        String s = "domain" + current + ".example";
                        current++;
                        return s;
                    }
                };
            }

            @Override
            public int size() {
                return 1_000_001;
            }
        };
    }

    private void putSnapshot(Descriptor descriptor, Set<String> domains) {
        stateMap().put(descriptor, new AtomicReference<>(new ListSnapshot(domains)));
    }

    private Set<String> snapshot(Descriptor descriptor) {
        return stateMap().get(descriptor).get().domainSet();
    }

    private FetchResult fetchAttempt(Descriptor descriptor, String url, String etag, String lastModified) {
        nextFetchSlot().set(0L);
        return (FetchResult) invoke("attemptFetch",
                new Class<?>[]{Descriptor.class, String.class, String.class, String.class},
                descriptor, url, etag, lastModified);
    }

    private Object fetchAttempt(Descriptor descriptor, String url, String etag, String lastModified,
                                ClassicHttpResponse response) {
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(), List.of(response)));
        return fetchAttempt(descriptor, url, etag, lastModified);
    }

    private Object fetchRaw(Descriptor descriptor, String url, ClassicHttpResponse response) {
        setStaticFinalField("FETCH_CLIENT", responseClient(new ArrayList<>(), List.of(response)));
        nextFetchSlot().set(0L);
        return invoke("fetchRaw", new Class<?>[]{Descriptor.class, String.class, String.class, String.class},
                descriptor, url, null, null);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static CloseableHttpClient responseClient(List<org.apache.hc.core5.http.ClassicHttpRequest> requests,
                                                      List<ClassicHttpResponse> responses) {
        Deque<ClassicHttpResponse> queuedResponses = new ArrayDeque<>(responses);
        CloseableHttpClient client = mock(CloseableHttpClient.class);

        try {
            doAnswer(invocation -> {
                requests.add(invocation.getArgument(0));
                HttpClientResponseHandler handler = invocation.getArgument(1);
                return handler.handleResponse(queuedResponses.removeFirst());
            }).when(client).execute(any(org.apache.hc.core5.http.ClassicHttpRequest.class),
                    any(HttpClientResponseHandler.class));
        } catch (IOException e) {
            throw new AssertionError("Could not stub fetch client", e);
        }
        return client;
    }

    private static ClassicHttpResponse response(int statusCode, String contentType, String body,
                                                String etag, String lastModified, String... extraHeader) {
        ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        Map<String, Header> headers = new HashMap<>();

        if (contentType != null) {
            headers.put("Content-Type", header(contentType));
        }
        if (etag != null) {
            headers.put("ETag", header(etag));
        }
        if (lastModified != null) {
            headers.put("Last-Modified", header(lastModified));
        }
        if (extraHeader.length == 2) {
            headers.put(extraHeader[0], header(extraHeader[1]));
        }

        when(response.getCode()).thenReturn(statusCode);
        when(response.getFirstHeader(any(String.class)))
                .thenAnswer(invocation -> headers.get(invocation.getArgument(0)));

        if (body != null) {
            HttpEntity entity = mock(HttpEntity.class);
            try {
                when(entity.getContent()).thenAnswer(invocation -> stream(body));
            } catch (IOException e) {
                throw new AssertionError("Could not stub response body", e);
            }
            when(response.getEntity()).thenReturn(entity);
        }
        return response;
    }

    private static Header header(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }

    private static InputStream stream(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static Map<Descriptor, AtomicReference<ListSnapshot>> stateMap() {
        return staticField("stateMap", Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<Descriptor, Map<String, FetchResult>> perUrlCache() {
        return staticField("perUrlCache", Map.class);
    }

    private static AtomicLong nextFetchSlot() {
        return staticField("nextFetchSlotMillis", AtomicLong.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> mutableEnvironment() {
        try {
            Map<String, String> environment = System.getenv();
            Field field = environment.getClass().getDeclaredField("m");
            return (Map<String, String>) UNSAFE.getObject(environment, UNSAFE.objectFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not access the process environment", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> caseInsensitiveEnvironment() {
        try {
            Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");
            Field field = processEnvironment.getDeclaredField("theCaseInsensitiveEnvironment");
            return (Map<String, String>) UNSAFE.getObject(UNSAFE.staticFieldBase(field),
                    UNSAFE.staticFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not access the process environment", e);
        }
    }

    private static void restoreEnvironmentValue(Map<String, String> environment, String key, String originalValue) {
        if (originalValue == null) {
            environment.remove(key);
        } else {
            environment.put(key, originalValue);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T descriptorField(Descriptor descriptor, String name) {
        try {
            Field field = Descriptor.class.getDeclaredField(name);
            field.setAccessible(true);
            return (T) UNSAFE.getObject(descriptor, UNSAFE.objectFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not read Descriptor." + name, e);
        }
    }

    private static void setDescriptorField(Descriptor descriptor, String name, Object value) {
        try {
            Field field = Descriptor.class.getDeclaredField(name);
            field.setAccessible(true);
            UNSAFE.putObject(descriptor, UNSAFE.objectFieldOffset(field), value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not set Descriptor." + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T staticField(String name, Class<T> type) {
        try {
            Field field = LocalListUtil.class.getDeclaredField(name);
            field.setAccessible(true);
            return (T) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not read LocalListUtil." + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T instanceField(LocalListUtil target, String name) {
        try {
            Field field = LocalListUtil.class.getDeclaredField(name);
            field.setAccessible(true);
            return (T) UNSAFE.getObject(target, UNSAFE.objectFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not read LocalListUtil." + name, e);
        }
    }

    private static void setInstanceField(LocalListUtil target, String name, Object value) {
        try {
            Field field = LocalListUtil.class.getDeclaredField(name);
            field.setAccessible(true);
            UNSAFE.putObject(target, UNSAFE.objectFieldOffset(field), value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not set LocalListUtil." + name, e);
        }
    }

    private static void setStaticField(String name, Object value) {
        try {
            Field field = LocalListUtil.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(null, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not set LocalListUtil." + name, e);
        }
    }

    private static void setStaticFinalField(String name, Object value) {
        try {
            Field field = LocalListUtil.class.getDeclaredField(name);
            field.setAccessible(true);
            UNSAFE.putObject(UNSAFE.staticFieldBase(field), UNSAFE.staticFieldOffset(field), value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not set LocalListUtil." + name, e);
        }
    }

    private static Object invoke(String name, Class<?>[] parameterTypes, Object... arguments) {
        try {
            Method method = LocalListUtil.class.getDeclaredMethod(name, parameterTypes);
            method.setAccessible(true);
            return method.invoke(null, arguments);
        } catch (InvocationTargetException e) {
            throw new ReflectionInvocationException(e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not invoke LocalListUtil." + name, e);
        }
    }

    private static void assertReflectionCause(Class<? extends Throwable> type, Runnable invocation) {
        assertThatThrownBy(invocation::run)
                .isInstanceOf(ReflectionInvocationException.class)
                .hasCauseInstanceOf(type);
    }

    private static final class ReflectionInvocationException extends RuntimeException {

        ReflectionInvocationException(Throwable cause) {
            super(cause);
        }
    }

    private static final Unsafe UNSAFE = unsafe();

    private static Unsafe unsafe() {
        try {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            return (Unsafe) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not obtain Unsafe", e);
        }
    }
}
