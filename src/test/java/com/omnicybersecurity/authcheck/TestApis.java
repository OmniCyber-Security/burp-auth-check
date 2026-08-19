package com.omnicybersecurity.authcheck;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Minimal stand-ins for the Burp API so the logic that does not touch the
 * network can be tested outside Burp. Only {@code logging()} is implemented;
 * anything else throws, which keeps tests honest about what they exercise.
 *
 * <p>Montoya's static factories ({@code HttpResponse.httpResponse(...)} and
 * friends) delegate to a factory that only exists inside Burp, so tests build
 * HTTP messages with the fakes in the {@code engine} test package instead.
 */
public final class TestApis {

    private TestApis() {
    }

    public static MontoyaApi montoyaApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                TestApis.class.getClassLoader(),
                new Class<?>[] { Logging.class },
                new LoggingHandler());

        return (MontoyaApi) Proxy.newProxyInstance(
                TestApis.class.getClassLoader(),
                new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> {
                    if ("logging".equals(method.getName())) {
                        return logging;
                    }
                    throw new UnsupportedOperationException(
                            "This test must not reach MontoyaApi." + method.getName() + "()");
                });
    }

    /** Swallows log calls; returns benign defaults for the rest. */
    private static final class LoggingHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            Class<?> returnType = method.getReturnType();
            if (returnType == void.class) {
                return null;
            }
            if (returnType == java.io.PrintStream.class) {
                return new java.io.PrintStream(java.io.OutputStream.nullOutputStream());
            }
            return null;
        }
    }
}
