package com.omnicybersecurity.authcheck.engine;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The worker-threads setting is the only throttle, so resizing must honour it exactly. */
class PoolResizeTest {

    private final ThreadPoolExecutor pool = new ThreadPoolExecutor(
            4, 4, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());

    @AfterEach
    void tearDown() {
        pool.shutdownNow();
    }

    @Test
    void shrinksToOneAndGrowsBack() {
        AuthCheckEngine.resize(pool, 1);
        assertEquals(1, pool.getCorePoolSize());
        assertEquals(1, pool.getMaximumPoolSize());

        AuthCheckEngine.resize(pool, 8);
        assertEquals(8, pool.getCorePoolSize());
        assertEquals(8, pool.getMaximumPoolSize());
    }

    @Test
    void oneThreadRunsQueuedTasksOneAtATimeWithoutDroppingAny() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(4);
        // Occupy all four threads, then shrink while they are busy.
        for (int i = 0; i < 4; i++) {
            pool.execute(() -> {
                started.countDown();
                await(release);
            });
        }
        assertTrue(started.await(5, TimeUnit.SECONDS));
        AuthCheckEngine.resize(pool, 1);

        AtomicInteger concurrent = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        CountDownLatch done = new CountDownLatch(10);
        for (int i = 0; i < 10; i++) {
            pool.execute(() -> {
                peak.accumulateAndGet(concurrent.incrementAndGet(), Math::max);
                sleep(5);
                concurrent.decrementAndGet();
                done.countDown();
            });
        }
        release.countDown();

        assertTrue(done.await(10, TimeUnit.SECONDS), "every queued task still runs");
        assertEquals(1, peak.get());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
