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
package net.foulest.ospreyproxy.providers.list;

import lombok.RequiredArgsConstructor;
import net.foulest.ospreyproxy.util.list.Descriptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for defining beans related to local list providers.
 */
@Configuration
@RequiredArgsConstructor
public class LocalListProviderConfig {

    /**
     * Defines a bean for the KAD Anti-Scam local list provider, which uses the KAD_ANTI_SCAM descriptor.
     *
     * @return A LocalListProvider instance configured for the KAD Anti-Scam list.
     */
    @Bean
    public LocalListProvider kadAntiScamProvider() {
        return new LocalListProvider(Descriptor.KAD_ANTI_SCAM);
    }

    /**
     * Defines a bean for the OpenPhish local list provider, which uses the OPEN_PHISH descriptor.
     *
     * @return A LocalListProvider instance configured for the OpenPhish list.
     */
    @Bean
    public LocalListProvider openPhishProvider() {
        return new LocalListProvider(Descriptor.OPEN_PHISH);
    }

    /**
     * Defines a bean for the PhishDestroy local list provider, which uses the PHISH_DESTROY descriptor.
     *
     * @return A LocalListProvider instance configured for the PhishDestroy list.
     */
    @Bean
    public LocalListProvider phishDestroyProvider() {
        return new LocalListProvider(Descriptor.PHISH_DESTROY);
    }

    /**
     * Defines a bean for the Phishunt.io local list provider, which uses the PHISHUNT_IO descriptor.
     *
     * @return A LocalListProvider instance configured for the Phishunt.io list.
     */
    @Bean
    public LocalListProvider phishuntProvider() {
        return new LocalListProvider(Descriptor.PHISHUNT_IO);
    }

    /**
     * Defines a bean for the Phishing.Database local list provider, which uses the PHISHING_DATABASE descriptor.
     *
     * @return A LocalListProvider instance configured for the Phishing.Database list.
     */
    @Bean
    public LocalListProvider phishingDatabaseProvider() {
        return new LocalListProvider(Descriptor.PHISHING_DATABASE);
    }

    /**
     * Defines a bean for the Red Flag Domains local list provider, which uses the RED_FLAG_DOMAINS descriptor.
     *
     * @return A LocalListProvider instance configured for the Red Flag Domains list.
     */
    @Bean
    public LocalListProvider redFlagDomainsProvider() {
        return new LocalListProvider(Descriptor.RED_FLAG_DOMAINS);
    }

    /**
     * Defines a bean for the SecureFeed local list provider, which uses the SECURE_FEED descriptor.
     *
     * @return A LocalListProvider instance configured for the SecureFeed list.
     */
    @Bean
    public LocalListProvider secureFeedProvider() {
        return new LocalListProvider(Descriptor.SECURE_FEED);
    }

    /**
     * Defines a bean for the SinkingYachts local list provider, which uses the SINKING_YACHTS descriptor.
     *
     * @return A LocalListProvider instance configured for the SinkingYachts list.
     */
    @Bean
    public LocalListProvider sinkingYachtsProvider() {
        return new LocalListProvider(Descriptor.SINKING_YACHTS);
    }

    /**
     * Defines a bean for the THREATfox local list provider, which uses the THREATFOX descriptor.
     *
     * @return A LocalListProvider instance configured for the THREATfox list.
     */
    @Bean
    public LocalListProvider threatfoxProvider() {
        return new LocalListProvider(Descriptor.THREATFOX);
    }

    /**
     * Defines a bean for the URLhaus local list provider, which uses the URLHAUS descriptor.
     *
     * @return A LocalListProvider instance configured for the URLhaus list.
     */
    @Bean
    public LocalListProvider urlhausProvider() {
        return new LocalListProvider(Descriptor.URLHAUS);
    }

    /**
     * Defines a bean for the Validin local list provider, which uses the VALIDIN descriptor.
     * This descriptor aggregates eight source feeds under the single {@code validin} endpoint.
     *
     * @return A LocalListProvider instance configured for the Validin list.
     */
    @Bean
    public LocalListProvider validinProvider() {
        return new LocalListProvider(Descriptor.VALIDIN);
    }
}
