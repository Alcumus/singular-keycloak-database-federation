package org.opensingular.dbuserprovider;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.component.ComponentModel;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.persistence.DataSourceProvider;
import org.opensingular.dbuserprovider.persistence.RDBMS;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class DBUserStorageProviderFactoryTest {

    @Test
    public void createShouldConfigureOnlyOnceWhenCalledConcurrently() throws Exception {
        TestFactory factory = new TestFactory();
        ComponentModel model = new ComponentModel();
        model.setId("component-1");
        model.setName("Test Provider");

        int concurrency = 8;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<DBUserStorageProvider>> futures = new ArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            futures.add(executor.submit(() -> {
                start.await();
                return factory.create(null, model);
            }));
        }

        start.countDown();

        List<DBUserStorageProvider> providers = new ArrayList<>();
        for (Future<DBUserStorageProvider> future : futures) {
            providers.add(future.get(5, TimeUnit.SECONDS));
        }

        for (DBUserStorageProvider provider : providers) {
            provider.close();
        }

        executor.shutdown();
        Assert.assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

        factory.close();

        Assert.assertEquals(1, factory.configureCalls.get());
        Assert.assertEquals(1, factory.closedProviderConfigs.get());
    }

    @Test
    public void validateConfigurationShouldRetireOldConfigAfterProviderClose() {
        TestFactory factory = new TestFactory();
        ComponentModel model = new ComponentModel();
        model.setId("component-1");
        model.setName("Test Provider");

        DBUserStorageProvider provider = factory.create(null, model);

        factory.validateConfiguration(null, null, model);

        Assert.assertEquals(2, factory.configureCalls.get());
        Assert.assertEquals(0, factory.closedProviderConfigs.get());

        provider.close();
        Assert.assertEquals(1, factory.closedProviderConfigs.get());

        factory.close();
        Assert.assertEquals(2, factory.closedProviderConfigs.get());
    }

    private static final class TestFactory extends DBUserStorageProviderFactory {
        private final AtomicInteger configureCalls = new AtomicInteger();
        private final AtomicInteger closedProviderConfigs = new AtomicInteger();

        @Override
        protected ProviderConfig configure(ComponentModel model) {
            configureCalls.incrementAndGet();
            return new ProviderConfig(new TestDataSourceProvider(closedProviderConfigs), new QueryConfigurations(
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "SHA-1",
                    RDBMS.SQL_SERVER,
                    false,
                    false
            ));
        }
    }

    private static final class TestDataSourceProvider extends DataSourceProvider {
        private final AtomicInteger closeCalls;
        private       boolean       closed;

        private TestDataSourceProvider(AtomicInteger closeCalls) {
            this.closeCalls = closeCalls;
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            closeCalls.incrementAndGet();
        }
    }
}