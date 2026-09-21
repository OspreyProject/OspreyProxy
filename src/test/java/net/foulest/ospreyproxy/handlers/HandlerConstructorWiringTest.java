package net.foulest.ospreyproxy.handlers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

import static org.assertj.core.api.Assertions.assertThat;

class HandlerConstructorWiringTest {

    @Test
    void springSelectsProductionConstructorsForHandlersWithTestConstructors() {
        assertSpringSelectsPublicConstructor(CheckHandler.class);
        assertSpringSelectsPublicConstructor(ProxyHandler.class);
        assertSpringSelectsPublicConstructor(ContactHandler.class);
    }

    private static void assertSpringSelectsPublicConstructor(Class<?> handlerType) {
        AutowiredAnnotationBeanPostProcessor processor = new AutowiredAnnotationBeanPostProcessor();
        processor.setBeanFactory(new DefaultListableBeanFactory());

        Constructor<?>[] candidates = processor.determineCandidateConstructors(
                handlerType, handlerType.getSimpleName());

        assertThat(candidates)
                .as("Spring constructor candidates for %s", handlerType.getSimpleName())
                .hasSize(1);
        assertThat(Modifier.isPublic(candidates[0].getModifiers())).isTrue();
    }
}
