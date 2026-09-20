/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util.dns;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class DNSUtilTest {

    @Test
    void buildsWireQueryAfterStrippingWhitespaceAndTrailingDot() {
        byte[] query = Base64.getUrlDecoder().decode(DNSUtil.buildBase64Query(" example.com. "));

        Assertions.assertThat(query).containsExactly(
                0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                3, 'c', 'o', 'm', 0,
                0, 1, 0, 1);
        Assertions.assertThat(DNSUtil.encodeHostParam(" example.com. ")).isEqualTo("example.com");
        Assertions.assertThatIllegalArgumentException()
                .isThrownBy(() -> DNSUtil.encodeHostParam("two words.example"));
    }

    @Test
    void rejectsInvalidEmptyOversizedAndOverlongLabels() {
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query("bad host"));
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query(""));
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query("a".repeat(254)));
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query("a".repeat(64) + ".com"));
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query(".example"));
        Assertions.assertThatIllegalArgumentException().isThrownBy(() -> DNSUtil.buildBase64Query("example..com"));
    }

    @Test
    void walkAnswersRejectsShortEmptyAndImplausibleAnswerCounts() {
        Assertions.assertThat(DNSUtil.walkAnswers(new byte[11], (type, clazz, ttl, data) -> true)).isFalse();
        Assertions.assertThat(DNSUtil.walkAnswers(header(0, 0), (type, clazz, ttl, data) -> true)).isFalse();
        Assertions.assertThat(DNSUtil.walkAnswers(header(0, 1001), (type, clazz, ttl, data) -> true)).isFalse();
    }

    @Test
    void walkAnswersInvokesPredicateForCompleteRecordsAndStopsAtFirstMatch() {
        byte[] response = responseWithQuestionAndAnswers(
                answer(DNSRecord.A, 1, 60, new byte[]{1, 2, 3, 4}),
                answer(DNSRecord.CNAME, 1, 20, name("target.example")));
        AtomicInteger invocations = new AtomicInteger();

        boolean matched = DNSUtil.walkAnswers(response, (type, clazz, ttl, data) -> {
            invocations.incrementAndGet();
            return type == DNSRecord.CNAME && clazz == 1 && ttl == 20
                    && "target.example".equals(DNSUtil.parseName(data));
        });

        Assertions.assertThat(matched).isTrue();
        Assertions.assertThat(invocations).hasValue(2);
        Assertions.assertThat(DNSUtil.walkAnswers(response, (type, clazz, ttl, data) -> false)).isFalse();
    }

    @Test
    void walkAnswersRejectsTruncatedQuestionAndMalformedOrTruncatedAnswers() {
        byte[] truncatedQuestion = concat(header(1, 1), new byte[]{0});
        byte[] missingAnswer = concat(header(0, 1), new byte[0]);
        byte[] truncatedName = concat(header(0, 1), new byte[]{5});
        byte[] overflowingRdata = concat(header(0, 1), answerPrefix(DNSRecord.A, 1, 0, 4), new byte[]{1});

        Assertions.assertThat(DNSUtil.walkAnswers(truncatedQuestion, (type, clazz, ttl, data) -> true)).isFalse();
        Assertions.assertThat(DNSUtil.walkAnswers(missingAnswer, (type, clazz, ttl, data) -> true)).isFalse();
        Assertions.assertThat(DNSUtil.walkAnswers(truncatedName, (type, clazz, ttl, data) -> true)).isFalse();
        Assertions.assertThat(DNSUtil.walkAnswers(overflowingRdata, (type, clazz, ttl, data) -> true)).isFalse();
    }

    @Test
    void parseNameHandlesRootPointersAndMalformedLabels() {
        Assertions.assertThat(DNSUtil.parseName(new byte[0])).isEmpty();
        Assertions.assertThat(DNSUtil.parseName(name("one.two"))).isEqualTo("one.two");
        Assertions.assertThat(DNSUtil.parseName(new byte[]{0})).isEmpty();
        Assertions.assertThat(DNSUtil.parseName(new byte[]{(byte) 0xC0, 0x0C})).isEmpty();
        Assertions.assertThat(DNSUtil.parseName(new byte[]{3, 'o', 'n', 'e', (byte) 0xC0, 0x0C})).isEqualTo("one");
        Assertions.assertThat(DNSUtil.parseName(new byte[]{4, 'o', 'n'})).isEmpty();
    }

    @Test
    void parseIpv4RequiresExactlyFourBytesAndTreatsBytesAsUnsigned() {
        Assertions.assertThat(DNSUtil.parseIPv4(new byte[]{(byte) 255, 0, 1, (byte) 128})).isEqualTo("255.0.1.128");
        Assertions.assertThat(DNSUtil.parseIPv4(new byte[0])).isNull();
        Assertions.assertThat(DNSUtil.parseIPv4(new byte[]{1, 2, 3})).isNull();
        Assertions.assertThat(DNSUtil.parseIPv4(new byte[]{1, 2, 3, 4, 5})).isNull();
    }

    public static byte[] messageWithAnswers(String host, List<Answer> answers) {
        byte[] questionName = encodeName(host);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{0x00, 0x00, (byte) 0x81, (byte) 0x80, 0x00, 0x01,
                0x00, (byte) answers.size(), 0x00, 0x00, 0x00, 0x00});
        out.writeBytes(questionName);
        out.writeBytes(new byte[]{0x00, 0x01, 0x00, 0x01});

        for (Answer answer : answers) {
            out.writeBytes(new byte[]{(byte) 0xC0, 0x0C});
            out.writeBytes(new byte[]{(byte) (answer.type() >>> 8), (byte) answer.type(), 0x00, 0x01});
            out.writeBytes(new byte[]{
                    (byte) (answer.ttl() >>> 24), (byte) (answer.ttl() >>> 16),
                    (byte) (answer.ttl() >>> 8), (byte) answer.ttl()});
            byte[] data = answer.rdata();
            out.writeBytes(new byte[]{(byte) (data.length >>> 8), (byte) data.length});
            out.writeBytes(data);
        }
        return out.toByteArray();
    }

    public static byte[] ipv4(String ip) {
        String[] parts = ip.split("\\.");
        byte[] data = new byte[4];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(parts[i]);
        }
        return data;
    }

    public static byte[] encodeName(String value) {
        return name(value);
    }

    public record Answer(int type, long ttl, byte[] rdata) {

    }

    private static byte[] header(int questions, int answers) {
        return new byte[]{
                0, 0, (byte) 0x81, (byte) 0x80,
                (byte) (questions >>> 8), (byte) questions,
                (byte) (answers >>> 8), (byte) answers,
                0, 0, 0, 0};
    }

    private static byte[] responseWithQuestionAndAnswers(byte[]... answers) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(1, answers.length));
        out.writeBytes(name("q.example"));
        out.writeBytes(new byte[]{0, 1, 0, 1});
        for (byte[] answer : answers) {
            out.writeBytes(answer);
        }
        return out.toByteArray();
    }

    private static byte[] answer(int type, int clazz, long ttl, byte[] rdata) {
        return concat(answerPrefix(type, clazz, ttl, rdata.length), rdata);
    }

    private static byte[] answerPrefix(int type, int clazz, long ttl, int length) {
        return new byte[]{
                (byte) 0xC0, 0x0C,
                (byte) (type >>> 8), (byte) type,
                (byte) (clazz >>> 8), (byte) clazz,
                (byte) (ttl >>> 24), (byte) (ttl >>> 16), (byte) (ttl >>> 8), (byte) ttl,
                (byte) (length >>> 8), (byte) length};
    }

    private static byte[] name(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : value.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
            out.write(bytes.length);
            out.writeBytes(bytes);
        }
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
