/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

/**
 * Utility class for Jackson ObjectMapper and pre-resolved JavaType instances to optimize JSON parsing and validation.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JacksonUtil {

    // Jackson mapper for parsing request bodies and validating upstream responses
    public static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNumberLength(1000)
                            .maxNestingDepth(10)
                            .maxStringLength(500_000)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .build())
            .build();

    // Pre-resolved JavaType for Map<String, String> to avoid construction overhead
    static final JavaType MAP_TYPE_STRING = MAPPER.constructType(
            new TypeReference<Map<String, String>>() {
            }
    );

    // Pre-resolved JavaType for Map<String, Object> to avoid construction overhead
    public static final JavaType MAP_TYPE_OBJECT = MAPPER.constructType(
            new TypeReference<Map<String, Object>>() {
            }
    );

    // Pre-resolved JavaType for List<String> to avoid construction overhead
    public static final JavaType LIST_TYPE = MAPPER.constructType(
            new TypeReference<List<String>>() {
            }
    );
}
