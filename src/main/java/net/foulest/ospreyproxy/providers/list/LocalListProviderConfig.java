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

import net.foulest.ospreyproxy.util.list.Descriptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for defining beans related to local list providers.
 */
@Configuration
public class LocalListProviderConfig {

    @Bean
    public LocalListProvider phishDestroyProvider() {
        return new LocalListProvider(Descriptor.PHISH_DESTROY);
    }

    @Bean
    public LocalListProvider phishingDatabaseProvider() {
        return new LocalListProvider(Descriptor.PHISHING_DATABASE);
    }
}
